package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
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
							Conn:                 a.Conn,
							LabInfo:              l,
						}
						event.UnassignedVpnLabs <- agentLab
						event.M.Lock()
						event.Labs[l.Tag] = agentLab
						event.M.Unlock()
						saveState(eventPool, statePath)
						continue
					}
					agentLab := &AgentLab{
						ParentAgent: ParentAgent{
							Name: a.Name,
							Url:  a.Url,
							Tls:  a.Tls,
						},
						Conn:                 a.Conn,
						EstimatedMemoryUsage: event.EstimatedMemoryUsagePerLab,
						LabInfo:              l,
					}
					event.UnassignedBrowserLabs <- agentLab
					event.M.Lock()
					event.Labs[l.Tag] = agentLab
					event.M.Unlock()
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
	ap.calculateTotalMemoryInstalled()

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

func (ap *AgentPool) GetAllAgents() map[string]*Agent {
	ap.M.RLock()
	defer ap.M.RUnlock()

	return ap.Agents
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

			// Start an environment on each available agent
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
					InitialLabs:     distributionMap[availableAgent.Name].initialLabs,
					ExerciseConfigs: eventConfig.ExerciseConfigs,
					TeamSize:        eventConfig.TeamSize,
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
			ap.M.RUnlock()
			return NoResourcesError
		}
	} else {
		ap.M.RUnlock()
		return NoAgentsConnected
	}
	return nil
}

type agentLabDistribution struct {
	initialLabs int32
	full        bool
}

// Returns a map of the lab distribution for available agents, based on how many labs should be spun up on each agent
func (ap *AgentPool) calculateLabDistribution(agentsAvailable []*Agent, eventPool *EventPool, eventConfig EventConfig, resourceEstimates ResourceEstimates) (map[string]*agentLabDistribution, error) {
	// Make sure the agents available are sorted by agent with largest weight first
	sort.SliceStable(agentsAvailable, func(p, q int) bool {
		return agentsAvailable[p].Weight > agentsAvailable[q].Weight
	})

	//Prepare the map to return
	agentLabDistributionMap := make(map[string]*agentLabDistribution)

	labsToDistribute := eventConfig.MaxLabs
Distributer:
	for _, agent := range agentsAvailable {
		if _, ok := agentLabDistributionMap[agent.Name]; !ok {
			// First time running the distributer
			log.Debug().Msg("agent not in lab distribution map")
			agentLabDistributionMap[agent.Name] = &agentLabDistribution{
				initialLabs: 0,
				full:        false,
			}
		}

		// In case agent has previously been assigned labs but do not have more resources.
		if agentLabDistributionMap[agent.Name].full {
			continue Distributer
		}
		currentEstimatedLabConsumption := agent.calculateCurrentEstimatedMemConsumption(eventPool)

		// Weight determines how many labs will be spun up before continuing to next agent
		for i := 0; i < int(agent.Weight); i++ {
			newMemoryConsumptionEstimate := uint64(agentLabDistributionMap[agent.Name].initialLabs)*resourceEstimates.EstimatedMemUsagePerLab + resourceEstimates.EstimatedMemUsagePerLab + currentEstimatedLabConsumption
			estimatedMemoryLeftOnAgent := agent.Resources.MemoryInstalled - newMemoryConsumptionEstimate
			// Check if memory of new lab will surpass threshholds
			if newMemoryConsumptionEstimate > agent.Resources.MemoryInstalled || estimatedMemoryLeftOnAgent < MemoryThreshHold*1000000000 {
				agentLabDistributionMap[agent.Name].full = true
				log.Debug().Str("agent", agent.Name).Msg("lab will surpass memory available")
				log.Debug().Str("agent", agent.Name).Int32("labs", agentLabDistributionMap[agent.Name].initialLabs).Msg("labs distributed to agent")
				continue Distributer
			}

			// All checks passed, add the lab to the agent
			agentLabDistributionMap[agent.Name].initialLabs += 1
			labsToDistribute -= 1
			if labsToDistribute == 0 {
				for _, agent := range agentsAvailable {
					if _, ok := agentLabDistributionMap[agent.Name]; !ok {
						// Make sure agent exists in map even though it has not been assigned any labs
						agentLabDistributionMap[agent.Name] = &agentLabDistribution{
							initialLabs: 0,
							full:        false,
						}
						continue
					}
					log.Debug().Str("agent", agent.Name).Bool("full", agentLabDistributionMap[agent.Name].full).Int32("labs distributed", agentLabDistributionMap[agent.Name].initialLabs).Msg("labs distributed to agent")
				}
				return agentLabDistributionMap, nil
			}
		}
	}

	if labsToDistribute > 0 {
		allFull := true
		for _, agent := range agentsAvailable {
			if !agentLabDistributionMap[agent.Name].full {
				allFull = false
			}
		}
		if allFull {
			return nil, NoResourcesError
		}
		goto Distributer
	}

	for _, agent := range agentsAvailable {
		log.Debug().Str("agent", agent.Name).Bool("full", agentLabDistributionMap[agent.Name].full).Int32("labs distributed", agentLabDistributionMap[agent.Name].initialLabs).Msg("labs distributed to agent")
	}
	return agentLabDistributionMap, nil
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
		ap.M.RUnlock()
		return NoAgentsConnected
	}
	return nil
}

// Creates a lab for a specified event with a specified type
func (ap *AgentPool) createLabForEvent(ctx context.Context, isVpn bool, event *Event, eventPool *EventPool) error {
	agentForLab, err := ap.selectAgentForLab(ctx, event.EstimatedMemoryUsagePerLab, eventPool, event)
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

func (ap *AgentPool) selectAgentForLab(ctx context.Context, estimatedMemUsagePerLab uint64, eventPool *EventPool, event *Event) (*Agent, error) {
	var availableAgents []*Agent
	for _, agent := range ap.Agents {
		client := aproto.NewAgentClient(agent.Conn)
		// Retrieve a list of environments, if the environment for this event is not running, skip the agent
		listEnvResp, err := client.ListEnvironments(ctx, &aproto.Empty{})
		if err != nil {
			log.Error().Err(err).Str("agent", agent.Name).Msg("error listing environments for agent")
			continue
		}
		envExists := listEnvResp.EventTags[event.Config.Tag]
		starting := listEnvResp.StartingEventTags[event.Config.Tag]
		closing := listEnvResp.ClosingEventTags[event.Config.Tag]
		if !envExists || starting || closing {
			log.Info().Str("agent", agent.Name).Msg("Agent cannot be selected for lab because of missing environment")
			continue
		}
		// Environment exists continue with calculations
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

// Calculates total available memory for the whole platform
func (ap *AgentPool) calculateTotalMemoryInstalled() {
	ap.M.Lock()
	defer ap.M.Unlock()
	var totalMemoryAvailable uint64 //
	var totalMemoryInstalled uint64
	for _, agent := range ap.Agents {
		//log.Debug().Str("agent", agent.Name).Uint64("memInstalled", agent.Resources.MemoryInstalled).Msg("memory installed on agent")
		if agent.StateLock {
			continue
		}
		totalMemoryAvailable += agent.Resources.MemoryAvailable
		totalMemoryInstalled += agent.Resources.MemoryInstalled
	}
	ap.TotalMemInstalled = totalMemoryInstalled
	//log.Debug().Uint64("TotalMemInstalled", ap.TotalMemInstalled).Msg("total memory installed")
	//log.Debug().Uint64("totalMemoryAvailable", totalMemoryAvailable).Msg("total memory available")

}

// Agent

// Calculates the currently estimated resource usage of an agent
// TODO We might need to look into also taking into consideration the teams that are in queue since they are actively still waiting for a lab
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

func (agentLab *AgentLab) updateLabInfo() {
	ctx := context.Background()
	agentClient := aproto.NewAgentClient(agentLab.Conn)
	agentResp, err := agentClient.GetLab(ctx, &aproto.GetLabRequest{LabTag: agentLab.LabInfo.Tag})
	if err != nil {
		log.Error().Err(err).Msg("error updating lab info")
		return
	}

	agentLab.LabInfo = agentResp.Lab
}

func (agentLab *AgentLab) close() error {
	ctx := context.Background()
	agentClient := aproto.NewAgentClient(agentLab.Conn)
	_, err := agentClient.CloseLab(ctx, &aproto.CloseLabRequest{LabTag: agentLab.LabInfo.Tag})
	if err != nil {
		log.Error().Err(err).Msg("error updating lab info")
		return err
	}
	return nil
}

// TODO Get more info from agent related to config to make sure that an older event with same tag is not used by the daemon.
func (d *daemon) agentSyncRoutine(ticker *time.Ticker) {
	log.Info().Msg("[agent-syncronisation-routine] starting routine")
	for {
		select {
		case <-ticker.C:
			ctx := context.Background()
			agents := d.agentPool.GetAllAgents()
			events := d.eventpool.GetAllEvents()

			for _, agent := range agents {
				client := aproto.NewAgentClient(agent.Conn)
				listEnvResp, err := client.ListEnvironments(ctx, &aproto.Empty{})
				if err != nil {
					log.Error().Err(err).Str("agent", agent.Name).Msg("[agent-syncronisation-routine] error listing environments on agent")
					continue
				}
				// If an event is running in the daemon but not on the agent, start it up
				for _, event := range events {
					eventConfig := event.GetConfig()
					envExists := listEnvResp.EventTags[eventConfig.Tag]
					starting := listEnvResp.StartingEventTags[eventConfig.Tag]
					if !envExists && !starting {
						log.Debug().Str("agent", agent.GetName()).Str("eventTag", eventConfig.Tag).Msg("[agent-syncronisation-routine] found daemon event not running on agent, starting the environment...")
						envConfig := aproto.CreatEnvRequest{
							EventTag: eventConfig.Tag,
							EnvType:  eventConfig.Type,
							// TODO Just temporarily using hardcoded vm config
							Vm: &aproto.VmConfig{
								Image:    eventConfig.VmName,
								MemoryMB: 4096,
								Cpu:      0,
							},
							InitialLabs:     0,
							ExerciseConfigs: eventConfig.ExerciseConfigs,
							TeamSize:        eventConfig.TeamSize,
						}
						go func(conf *aproto.CreatEnvRequest, client aproto.AgentClient) {
							if _, err := client.CreateEnvironment(ctx, conf); err != nil {
								log.Error().Err(err).Str("agentName", agent.GetName()).Msg("[agent-syncronisation-routine] error creating environment for agent")
								return
							}
						}(&envConfig, client)
					}
				}
				// If an event is running on the agent but not in the daemon, close it down
				for envTag := range listEnvResp.EventTags {
					_, err := d.eventpool.GetEvent(envTag)
					if err != nil {
						closing := listEnvResp.ClosingEventTags[envTag]
						if closing {
							continue
						}
						log.Debug().Str("agent", agent.GetName()).Str("envTag", envTag).Msg("[agent-syncronisation-routine] found agent environment not running in daemon, closing the environment...")
						go func(client aproto.AgentClient) {
							if _, err := client.CloseEnvironment(ctx, &aproto.CloseEnvRequest{EventTag: envTag}); err != nil {
								log.Error().Err(err).Str("agentName", agent.GetName()).Msg("[agent-syncronisation-routine] error closing environment for agent")
								return
							}
						}(client)
					}

				}
			}
		}
	}
}

func (agent *Agent) GetName() string {
	agent.M.RLock()
	defer agent.M.RUnlock()

	return agent.Name
}

func (d *daemon) agentReconnectionRoutine(ticker *time.Ticker) {
	log.Info().Msg("[agent-reconnection-routine] starting routine")
	for range ticker.C {
		ctx := context.Background()
		dbAgents, err := d.db.GetAgents(ctx)
		if err != nil {
			log.Error().Err(err).Msg("[agent-reconnection-routine] error getting agents from database")
			continue
		}

		for _, dbAgent := range dbAgents {
			if _, err := d.agentPool.getAgent(dbAgent.Name); err != nil {
				log.Debug().Str("agent", dbAgent.Name).Msg("[agent-reconnection-routine] agent not found in agentpool, reconnecting...")
				serviceConf := ServiceConfig{
					Grpc:       dbAgent.Url,
					AuthKey:    dbAgent.AuthKey,
					SignKey:    dbAgent.SignKey,
					TLSEnabled: dbAgent.Tls,
				}
				conn, memoryInstalled, err := NewAgentConnection(serviceConf)
				if err != nil {
					log.Error().Err(err).Msg("error reconnecting to agent")
					continue
				}

				streamCtx, cancel := context.WithCancel(context.Background())
				agentForPool := &Agent{
					M:            sync.RWMutex{},
					Name:         dbAgent.Name,
					Url:          dbAgent.Url,
					Tls:          dbAgent.Tls,
					Conn:         conn,
					Weight:       dbAgent.Weight,
					RequestsLeft: dbAgent.Weight,
					StateLock:    false,
					Errors:       []error{},
					Close:        cancel,
					Resources: AgentResources{
						MemoryInstalled: memoryInstalled,
					},
				}

				if err := d.agentPool.connectToStreams(streamCtx, agentForPool, d.eventpool, d.conf.StatePath); err != nil {
					log.Error().Err(err).Msg("error connecting to agent streams")
					continue
				}

				d.agentPool.addAgent(agentForPool)
				d.eventpool.M.RLock()
				for _, event := range d.eventpool.Events {
					event.M.Lock()
					for _, lab := range event.Labs {

						if lab.ParentAgent.Name == agentForPool.Name {
							lab.Conn = conn
						}
					}
					event.M.Unlock()
				}
				d.eventpool.M.RUnlock()
			}
		}
	}
}
