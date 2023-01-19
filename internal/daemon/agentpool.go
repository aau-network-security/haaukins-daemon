package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	aproto "github.com/aau-network-security/haaukins-agent/pkg/proto"
	"github.com/rs/zerolog/log"
)

type EventType uint32

const (
	// LabType
	TypeBeginner EventType = iota
	TypeAdvanced
)

func (eventType EventType) String() string {
	switch eventType {
	case TypeBeginner:
		return "beginner"
	case TypeAdvanced:
		return "advanced"
	}

	log.Error().Msg("type did not match any existing labType")
	return ""
}

var (
	AllAgentsReturnedErr        = errors.New("all agents returned error on creating environment")
	NoAgentsConnected           = errors.New("no agents connected")
	NoResourcesError            = errors.New("estimated memory usage of event is larger than what is available")
	MemoryThreshHold     uint64 = 5 // In GB
)

// Connects the daemon to an agent's streams (monitoring etc.)
func (ap *AgentPool) connectToStreams(ctx context.Context, a *Agent, eventPool *EventPool, statePath string) error {
	if err := ap.connectToMonitoringStream(ctx, a, eventPool, statePath); err != nil {
		return err
	}
	return nil
}

// Send a heartbeat to all agents in the database, remove/add agent if connection status changes
func (ap *AgentPool) connectToMonitoringStream(routineCtx context.Context, a *Agent, eventPool *EventPool, statePath string) error {
	client := aproto.NewAgentClient(a.Conn)
	stream, err := client.MonitorStream(routineCtx)
	log.Debug().Msg("connecting to monitor stream")
	if err != nil {
		return fmt.Errorf("error connecting to labStream: %v", err)
	}

	go func(ctx context.Context, stream aproto.Agent_MonitorStreamClient) {
		defer func() {
			if recover() != nil {
				log.Debug().Msg("channel closed while sending team to queue")
			}
		}()
		for {
			select {
			case <-ctx.Done():
				log.Debug().Str("agentName", a.Name).Msg("agent was signaled to close connections")
				if err := stream.CloseSend(); err != nil {
					log.Error().Err(err).Msg("error calling CloseSend()")
				}
				return
			default:
				if err := stream.Send(&aproto.PingRequest{Ping: "ping"}); err != nil {
					log.Error().Err(err).Msg("error sending monitoring ping request")
					if err == io.EOF {
						ap.removeAgent(a.Name)
						return
					}
					continue
				}
				msg, err := stream.Recv()
				if err != nil {
					log.Error().Err(err).Msg("error recieving monitoring message")
					if err == io.EOF {
						ap.removeAgent(a.Name)
						return
					}
					continue
				}

				for _, l := range msg.NewLabs {
					labJson, _ := json.Marshal(l) // Debugging purposes
					log.Debug().Str("agent", a.Name).Str("lab-tag", l.Tag).Msgf("recieved lab from agent: %s", labJson)

					event, err := eventPool.GetEvent(l.EventTag)
					if err != nil {
						log.Error().Err(err).Msg("error getting event")
						continue
					}

					if l.IsVPN {
						agentLab := &AgentLab{
							ParentAgent: ParentAgent{
								Name: a.Name,
								Url:  a.Url,
								Tls:  a.Tls,
							},
							EstimatedMemoryUsage: event.EstimatedMemoryUsagePerLab - vmAvrMemoryUsage,
							LabInfo:              l,
						}
						event.UnassignedVpnLabs <- agentLab
						event.Labs[l.Tag] = agentLab
						saveState(eventPool, statePath)
						continue
					}
					agentLab := &AgentLab{
						ParentAgent: ParentAgent{
							Name: a.Name,
							Url:  a.Url,
							Tls:  a.Tls,
						},
						EstimatedMemoryUsage: event.EstimatedMemoryUsagePerLab,
						LabInfo:              l,
					}
					event.UnassignedBrowserLabs <- agentLab
					event.Labs[l.Tag] = agentLab
					saveState(eventPool, statePath)
					continue
				}
				ap.updateAgentMetrics(a.Name, msg)
				//log.Debug().Str("hb", msg.Hb).Float64("cpu", msg.Resources.Cpu).Float64("mem", msg.Resources.Mem).Uint64("memAvailable", msg.Resources.MemAvailable).Msg("monitoring parameters ")
			}
			time.Sleep(1 * time.Second)
		}
	}(routineCtx, stream)
	return nil
}

// Adds an successfully connected agent to the agent pool
func (ap *AgentPool) addAgent(agent *Agent) {
	ap.M.Lock()
	defer ap.M.Unlock()

	ap.Agents[agent.Name] = agent
}

// Removes an agent from the agent pool when it is no longer connected
func (ap *AgentPool) removeAgent(name string) error {
	ap.M.Lock()
	defer ap.M.Unlock()

	agent, ok := ap.Agents[name]
	if !ok {
		return fmt.Errorf("no agent found with name: \"%s\" in agentpool", name)
	}
	agent.Close()
	agent.Conn.Close()
	delete(ap.Agents, name)

	return nil
}

// Sets the statelock value of an agent
func (ap *AgentPool) updateAgentState(name string, lock bool) error {
	ap.M.Lock()
	defer ap.M.Unlock()

	_, ok := ap.Agents[name]
	if !ok {
		return fmt.Errorf("no agent found with name: \"%s\" in agentpool", name)
	}

	ap.Agents[name].StateLock = lock
	return nil
}

// Updates all agent metrics and recalculates the weights based on the new values supplied
func (ap *AgentPool) updateAgentMetrics(name string, msg *aproto.MonitorResponse) (*Agent, error) {
	ap.M.Lock()
	_, ok := ap.Agents[name]
	if !ok {
		ap.M.Unlock()
		return nil, fmt.Errorf("no agent found with name: \"%s\" in agentpool", name)
	}

	ap.Agents[name].Resources.Cpu = msg.Resources.Cpu
	ap.Agents[name].Resources.Memory = msg.Resources.MemPercentUsed
	ap.Agents[name].Resources.MemoryAvailable = msg.Resources.MemAvailable
	ap.Agents[name].Resources.ContainerCount = msg.Resources.ContainerCount
	ap.Agents[name].Resources.VmCount = msg.Resources.VmCount
	ap.Agents[name].Resources.LabCount = msg.Resources.LabCount
	ap.Agents[name].Resources.MemoryInstalled = msg.Resources.MemInstalled
	ap.Agents[name].QueuedTasks = msg.QueuedTasks
	ap.M.Unlock()
	//log.Debug().Msg("calculating weights")
	ap.calculateWeightsAndTotalMemoryInstalled()

	return ap.Agents[name], nil
}

// Returns an agent from the agent pool
func (ap *AgentPool) getAgent(name string) (*Agent, error) {
	ap.M.RLock()
	defer ap.M.RUnlock()

	agent, ok := ap.Agents[name]
	if !ok {
		return nil, fmt.Errorf("no agent found with name: \"%s\" in agentpool", name)
	}

	return agent, nil
}

func (ap *AgentPool) createNewEnvOnAvailableAgents(ctx context.Context, eventPool *EventPool, eventConfig EventConfig, resourceEstimates ResourceEstimates) error {
	ap.M.RLock()

	if len(ap.Agents) > 0 {
		var m sync.Mutex
		var wg sync.WaitGroup
		var errs []error
		var agentsAvailable []*Agent
		// Since it is cannot be assumed that all agents are available at all times
		// We make a list of agents available
		for _, agent := range ap.Agents {
			if agent.StateLock || agent.Resources.MemoryAvailable < MemoryThreshHold*1000000000 {
				log.Debug().Str("agentName", agent.Name).Msg("Agent either statelocked or dont have enough resources")
			}
			agentsAvailable = append(agentsAvailable, agent)
		}

		// As labs are coming in 1 by 1 we need to make sure that we have some kind of real time variable to check for resource usage
		estimatedMemLeft := ap.TotalMemInstalled - resourceEstimates.EstimatedMemorySpent
		// Check if potential event memory usage will be larger than the total memory installed
		if resourceEstimates.EstimatedMemUsage > estimatedMemLeft { // Prevent integer overflow in the variable estimatedMemLeftAfterNewEvent below
			log.Debug().Msg("to many resources requested from event")
			ap.M.RUnlock()
			return NoResourcesError
		} else {
			estimatedMemLeftAfterNewEvent := estimatedMemLeft - resourceEstimates.EstimatedMemUsage
			log.Debug().Uint64("memAfterEvent", estimatedMemLeftAfterNewEvent).Msg("Total memory left when event is started")
			// Checking weather the event will surpass the set memory threshold of the whole platform
			if estimatedMemLeftAfterNewEvent < MemoryThreshHold*1000000000*uint64(len(agentsAvailable)) {
				log.Debug().Msg("to many resources requested from event")
				ap.M.RUnlock()
				return NoResourcesError
			}
		}

		if len(agentsAvailable) > 0 {
			ap.M.RUnlock()
			// Calculate the distribution map
			distributionMap, err := ap.calculateLabDistribution(agentsAvailable, eventPool, eventConfig, resourceEstimates)
			if err != nil {
				log.Error().Err(err).Msg("error calculating lab distribution")
				return err
			}

			// Just debugging
			for agent, distribution := range distributionMap {
				log.Debug().Str("agentName", agent).Bool("agentFull", distribution.full).Int32("initialLabs", distribution.initialLabs).Msg("Initial labs for agent")
			}

			for _, availableAgent := range agentsAvailable {
				envConfig := aproto.CreatEnvRequest{
					EventTag: eventConfig.Tag,
					EnvType:  eventConfig.Type,
					// TODO Just temporarily using hardcoded vm config
					Vm: &aproto.VmConfig{
						Image:    eventConfig.VmName,
						MemoryMB: 4096,
						Cpu:      0,
					},
					InitialLabs: distributionMap[availableAgent.Name].initialLabs,
					Exercises:   eventConfig.ExerciseTags,
					TeamSize:    eventConfig.TeamSize,
				}
				wg.Add(1)
				go func(conf *aproto.CreatEnvRequest, a *Agent) {
					defer wg.Done()

					if a.StateLock {
						errs = append(errs, errors.New("agent is statelocked"))
						log.Error().Str("agentName", a.Name).Msg("agent is statelocked")
						return
					}

					client := aproto.NewAgentClient(a.Conn)

					if _, err := client.CreateEnvironment(ctx, conf); err != nil {
						log.Error().Err(err).Str("agentName", a.Name).Msg("error creating environment for agent")
						m.Lock()
						errs = append(errs, err)
						m.Unlock()
					}
				}(&envConfig, availableAgent)
			}
			wg.Wait()
			if len(errs) == len(agentsAvailable) {
				return AllAgentsReturnedErr
			}
		} else {
			return NoResourcesError
		}
	} else {
		return NoAgentsConnected
	}
	return nil
}

type agentLabDistribution struct {
	initialLabs int32
	full        bool
}

// calculateLabDistribution returns a map of type agentLabDistribution, the key is the agentName, the main value is the initialLabs
// It works by using the weights decided by whoever setup the agents to determine how many labs each agent should spin up
//
// It does not only take weights into account, it also takes into account the estimated memory usage, and if the amount of labs
// will go above the threshold the remaining labs will be put into the labsRemainingToBeDistributed variable count.
//
// The algorithm will run in rounds, first trying to distribute the labs by weight. If all agents have enough resources
// there will only be one round. However if there are any labs remaining it will try to distribute the remaining labs
// to agents which are not resource capped, hence the full value in the agentLabDistribution type. If there are labs remaining
// and all available agents are full, it will return an error and the requested event will not be started.
//
// Since we are working with floats, before we return the distribution we check if there are to many or to little labs.
// In the case of to many labs, it will deduct labs which has recieved the least initialLabs then return the map.
// In case of to little labs, the difference will be pushed to the labsRemainingToBeDistributed variable,
// and more rounds will be run to compensate for the missing labs
// Once everything fits, it will return the map
func (ap *AgentPool) calculateLabDistribution(agentsAvailable []*Agent, eventPool *EventPool, eventConfig EventConfig, resourceEstimates ResourceEstimates) (map[string]*agentLabDistribution, error) {
	// ap.M.RLock()
	// defer ap.M.RUnlock()

	// Calculate the total weightSum of all available agents
	var weightSum int32 = 0
	for _, agent := range agentsAvailable {
		weightSum += agent.Weight
	}
	log.Debug().Int32("WeightSum", weightSum).Msg("Calculated weightsum for available agents")

	// Creating the actual map
	agentLabDistributionMap := make(map[string]*agentLabDistribution)
	// Creating the labsremaining counter
	var labsRemainingToBeDistributed int32 = 0
	for {
		// If first round or there are labs remaining after the first round
		if len(agentLabDistributionMap) == 0 || labsRemainingToBeDistributed > 0 {
			allFull := true

			// To keep track of how many labs was taken from remaining labs
			// Has to be deducted at the end or else you cant correctly calculate the correct distribution of remaining labs
			var labsTakenFromRemaining int32 = 0

			// When an agent is full we add its name to this slice to deduct its weight from the weightsum after each round
			fullAgents := []string{}
		Inner:
			for _, agent := range agentsAvailable {
				log.Debug().Int32("weightSum", weightSum).Msgf("Float value of calculation: %f", float64(labsRemainingToBeDistributed)*(float64(agent.Weight)/float64(weightSum)))
				// By default we calculate the agent's initial labs from the remaining labs
				// unless it is the first round
				agentInitialLabs := int32(math.Round(float64(labsRemainingToBeDistributed) * (float64(agent.Weight) / float64(weightSum))))
				agentDistribution, agentExists := agentLabDistributionMap[agent.Name]
				if !agentExists {
					log.Debug().Msg("First time")
					agentLabDistributionMap[agent.Name] = &agentLabDistribution{
						initialLabs: 0,
						full:        false,
					}
					log.Debug().Msgf("Float value of calculation: %f", float64(eventConfig.MaxLabs)*(float64(agent.Weight)/float64(weightSum)))
					agentInitialLabs = int32(math.Round(float64(eventConfig.MaxLabs) * (float64(agent.Weight) / float64(weightSum))))
				} else {
					// Ignore agent if it has no more resources
					if agentDistribution.full {
						continue Inner
					}
				}
				log.Debug().Int32("labsRemaining", labsRemainingToBeDistributed).Msg("Labs remaining")
				log.Debug().Str("agentName", agent.Name).Int32("initialLabs", agentInitialLabs).Msg("InitialLabs for agent")

				currentEstimatedLabConsumption := agent.calculateCurrentEstimatedMemConsumption(eventPool)
				log.Debug().Str("agentName", agent.Name).Uint64("currentEstimatedLabConsumption", currentEstimatedLabConsumption).Msg("Current summed memory usage estimation for agent")

				// When adding remaining labs to an agent we have to take the estimated memory usage of labs already
				// added in the previous rounds into account
				initialLabsEstimatedLabUsage := uint64(agentLabDistributionMap[agent.Name].initialLabs) * resourceEstimates.EstimatedMemUsagePerLab
			InnerInner:
				for i := 0; i < int(agentInitialLabs); i++ {
					// For each lab keep increasing the memory consumption estimate until you reach the limit
					// If the limit is not reached no labs will be pushed to the labsRemaining variable
					newMemoryConsumptionEstimate := currentEstimatedLabConsumption + initialLabsEstimatedLabUsage + resourceEstimates.EstimatedMemUsagePerLab*uint64(i+1)

					// Since we are substracting this variable from the memory installed value of the agent further down
					// We have to make sure it is not actually bigger and will cause and interger overflow
					if newMemoryConsumptionEstimate > agent.Resources.MemoryInstalled {
						log.Debug().Str("agentName", agent.Name).Int32("initialLabs", agentLabDistributionMap[agent.Name].initialLabs).Int32("labsForRemainder", agentInitialLabs-int32(i)).Msg("agent memory full")
						agentLabDistributionMap[agent.Name].full = true
						fullAgents = append(fullAgents, agent.Name)
						labsRemainingToBeDistributed += agentInitialLabs - int32(i)
						break InnerInner
					} else {
						estimatedMemoryLeft := agent.Resources.MemoryInstalled - newMemoryConsumptionEstimate
						// Checks if this lab will make the memory usage pass the threshold
						if estimatedMemoryLeft < MemoryThreshHold*1000000000 {
							log.Debug().Str("agentName", agent.Name).Int32("initialLabs", agentLabDistributionMap[agent.Name].initialLabs).Int32("labsForRemainder", agentInitialLabs-int32(i)).Msg("lab will surpass memory usage threshhold")
							agentLabDistributionMap[agent.Name].full = true
							fullAgents = append(fullAgents, agent.Name)
							labsRemainingToBeDistributed += agentInitialLabs - int32(i)
							break InnerInner
						}
						agentLabDistributionMap[agent.Name].initialLabs += 1
						if agentExists {
							labsTakenFromRemaining += 1
						}
					}
				}
				// If the agent is still not full after it has been assigned the labs
				// All agents are not capped
				if !agentLabDistributionMap[agent.Name].full {
					allFull = false
				}
				//time.Sleep(1 * time.Second) // Debugging purposes
			}

			// If any agents went capped during the round, deduct their weight from the weightsum
			for _, agentName := range fullAgents {
				agent, err := ap.getAgent(agentName)
				if err != nil {
					return nil, errors.New("could not find agent in agentPool when deducting weight from sum")
				}
				weightSum -= agent.Weight
				log.Debug().Str("agent", agent.Name).Int32("newSum", weightSum).Msg("New weightsum since some agents are full")
			}

			// Substract the labstaken from labs remaining
			labsRemainingToBeDistributed -= labsTakenFromRemaining

			// In case all labs are capped but there are still labsremaining to be assigned
			if labsRemainingToBeDistributed > 0 && allFull {
				return nil, NoResourcesError
			}
		} else {
			var numberOfLabsDistributed int32 = 0
			for _, distribution := range agentLabDistributionMap {
				numberOfLabsDistributed += distribution.initialLabs
			}

			// The following is to recover from any loss or gain in labs from rounding
			if numberOfLabsDistributed > eventConfig.MaxLabs {
				var min string
				first := true
				// Finding the agent with least amount of labs assigned is also the agent with least ram available or least weight
				for agentName, distribution := range agentLabDistributionMap {
					if first {
						min = agentName
						first = false
						continue
					}
					if distribution.initialLabs < agentLabDistributionMap[min].initialLabs {
						min = agentName
					}
				}
				numberOfToManyLabs := numberOfLabsDistributed - eventConfig.MaxLabs
				log.Debug().Str("agent", min).Int32("labsOverMax", numberOfToManyLabs).Msg("to many labs distributed, deducting from agent with least resources")
				agentLabDistributionMap[min].initialLabs -= numberOfToManyLabs
			} else if numberOfLabsDistributed < eventConfig.MaxLabs {
				// We need more labs, so add to labsRemaining and run 1 more cycle
				labsRemainingToBeDistributed = eventConfig.MaxLabs - numberOfLabsDistributed
				log.Debug().Int32("labsRemaining", labsRemainingToBeDistributed).Msg("Not anough labs distributed, pushing labs into labsremaining")
				continue
			}
			return agentLabDistributionMap, nil
		}
	}

}

// Closes a specific environment on all agents
func (ap *AgentPool) closeEnvironmentOnAllAgents(ctx context.Context, eventTag string) error {
	ap.M.RLock()

	if len(ap.Agents) > 0 {
		var m sync.Mutex
		var wg sync.WaitGroup
		var errs []error
		for _, a := range ap.Agents {
			wg.Add(1)
			go func(eventTag string, a *Agent) {
				defer wg.Done()

				if a.StateLock {
					errs = append(errs, errors.New("agent is statelocked"))
					log.Error().Str("agentName", a.Name).Msg("agent is statelocked")
					return
				}

				client := aproto.NewAgentClient(a.Conn)

				if _, err := client.CloseEnvironment(ctx, &aproto.CloseEnvRequest{EventTag: eventTag}); err != nil {
					log.Error().Err(err).Str("agentName", a.Name).Msg("error closing environment for agent")
					m.Lock()
					errs = append(errs, err)
					m.Unlock()
				}
			}(eventTag, a)
		}
		ap.M.RUnlock()
		wg.Wait()

		if len(errs) == len(ap.Agents) {
			return AllAgentsReturnedErr
		}
	} else {
		return NoAgentsConnected
	}
	return nil
}

// Creates a lab for a specified event with a specified type
func (ap *AgentPool) createLabForEvent(ctx context.Context, isVpn bool, event *Event, eventPool *EventPool) error {
	agentForLab, err := ap.selectAgentForLab(event.EstimatedMemoryUsagePerLab, eventPool)
	if err != nil {
		return errors.New("no suitable agent found")
	}
	log.Debug().Str("agent", agentForLab.Name).Int32("requestsLeft", agentForLab.RequestsLeft).Msg("agent selected for lab creation")
	client := aproto.NewAgentClient(agentForLab.Conn)

	req := &aproto.CreateLabRequest{
		EventTag: event.Config.Tag,
		IsVPN:    isVpn,
	}
	if _, err := client.CreateLabForEnv(ctx, req); err != nil {
		return err
	}

	return nil
}

func (ap *AgentPool) selectAgentForLab(estimatedMemUsagePerLab uint64, eventPool *EventPool) (*Agent, error) {
	var availableAgents []*Agent
	for _, agent := range ap.Agents {
		currentEstimatedMemConsumption := agent.calculateCurrentEstimatedMemConsumption(eventPool)
		memConsumptionAfterNewLab := currentEstimatedMemConsumption + estimatedMemUsagePerLab
		if agent.StateLock || memConsumptionAfterNewLab > agent.Resources.MemoryInstalled ||
			agent.Resources.MemoryInstalled-memConsumptionAfterNewLab < MemoryThreshHold*(10^9) {
			log.Debug().Str("agent", agent.Name).Uint64("currentConsumtion", currentEstimatedMemConsumption).
				Uint64("memConsumptionAfterNewLab", memConsumptionAfterNewLab).Uint64("memInstalled", agent.Resources.MemoryInstalled).
				Msg("Agent is not available to create labs")
			continue
		}
		availableAgents = append(availableAgents, agent)
	}

	if len(availableAgents) == 0 {
		return nil, errors.New("no agents currently available")
	}

SelectAgent:
	var agentWithMaxWeight *Agent = &Agent{
		Name:   "placeholder",
		Weight: 0,
	}
	first := true
	for _, agent := range availableAgents {
		if first && agent.RequestsLeft > 0 {
			first = false
			agentWithMaxWeight = agent
		}
		if agent.Weight > agentWithMaxWeight.Weight && agent.RequestsLeft > 0 {
			agentWithMaxWeight = agent
		}
	}
	if agentWithMaxWeight.Name != "placeholder" {
		agentWithMaxWeight.RequestsLeft -= 1
	} else { // No requests left on available agents, resetting
		log.Debug().Msg("Resetting requests left for all agents")
		ap.resetRequestsLeft()
		goto SelectAgent
	}

	return agentWithMaxWeight, nil
}

func (ap *AgentPool) resetRequestsLeft() {
	ap.M.Lock()
	defer ap.M.Unlock()

	for _, agent := range ap.Agents {
		agent.RequestsLeft = agent.Weight
	}
}

// Calculates initial lab weights based on remaining memory available on each agent
// (Only relevant for beginner type events)
func (ap *AgentPool) calculateWeightsAndTotalMemoryInstalled() {
	ap.M.Lock()
	defer ap.M.Unlock()
	var totalMemoryAvailable uint64 //
	var totalMemoryInstalled uint64
	var availableAgents []*Agent
	for _, agent := range ap.Agents {
		// Exclude ag
		// TODO Use a memory threshold instead of percentage
		//log.Debug().Str("agent", agent.Name).Uint64("memInstalled", agent.Resources.MemoryInstalled).Msg("memory installed on agent")
		if agent.StateLock {
			ap.AgentWeights[agent.Name] = 0
			continue
		}
		totalMemoryAvailable += agent.Resources.MemoryAvailable
		totalMemoryInstalled += agent.Resources.MemoryInstalled
		availableAgents = append(availableAgents, agent)
	}
	ap.TotalMemInstalled = totalMemoryInstalled
	//log.Debug().Uint64("TotalMemInstalled", ap.TotalMemInstalled).Msg("total memory installed")
	//log.Debug().Uint64("totalMemoryAvailable", totalMemoryAvailable).Msg("total memory available")

	for _, agent := range availableAgents {
		if agent.StateLock {
			continue
		}
		weight := float64(agent.Resources.MemoryAvailable) / float64(totalMemoryAvailable)
		if math.IsNaN(weight) || weight <= 0 {
			weight = 0
		}
		ap.AgentWeights[agent.Name] = weight
		//log.Debug().Float64("calculated weight", ap.AgentWeights[agent.Name]).Msgf("weight for agent: %s", agent.Name)
	}
}

// Agent

func (agent *Agent) calculateCurrentEstimatedMemConsumption(eventPool *EventPool) uint64 {
	// Get all labs for a specific agent including their estimated resource usage
	agentLabs := eventPool.GetAllAgentLabsForAgent(agent.Name)

	// Summarize the currently estimated resource usage of an agent
	var currentEstimatedLabConsumption uint64 = 0
	for _, agentLab := range agentLabs {
		currentEstimatedLabConsumption += agentLab.EstimatedMemoryUsage
	}

	return currentEstimatedLabConsumption
}
