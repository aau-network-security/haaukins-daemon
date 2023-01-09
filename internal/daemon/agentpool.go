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
	AllAgentsReturnedErr = errors.New("all agents returned error on creating environment")
	NoAgentsConnected    = errors.New("no agents connected")
	NoResourcesError     = errors.New("estimated memory usage of event is larger than what is available")
)

// Connects the daemon to an agent's streams (monitoring etc.)
func (ap *AgentPool) connectToStreams(ctx context.Context, newLabs chan aproto.Lab, a *Agent, eventPool *EventPool) error {
	if err := ap.connectToMonitoringStream(ctx, newLabs, a, eventPool); err != nil {
		return err
	}
	return nil
}

// Send a heartbeat to all agents in the database, remove/add agent if connection status changes
func (ap *AgentPool) connectToMonitoringStream(routineCtx context.Context, newLabs chan aproto.Lab, a *Agent, eventPool *EventPool) error {
	client := aproto.NewAgentClient(a.Conn)
	stream, err := client.MonitorStream(routineCtx)
	log.Debug().Msg("connecting to monitor stream")
	if err != nil {
		return fmt.Errorf("error connecting to labStream: %v", err)
	}

	go func(ctx context.Context, stream aproto.Agent_MonitorStreamClient, newLabs chan aproto.Lab) {
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
							ParentAgent: a.Name,
							LabInfo:     l,
						}
						event.UnassignedVpnLabs <- agentLab
						event.Labs[l.Tag] = agentLab
						continue
					}
					agentLab := &AgentLab{
						ParentAgent: a.Name,
						LabInfo:     l,
					}
					event.UnassignedBrowserLabs <- agentLab
					event.Labs[l.Tag] = agentLab
					continue
				}
				ap.updateAgentMetrics(a.Name, msg)
				//log.Debug().Str("hb", msg.Hb).Float64("cpu", msg.Resources.Cpu).Float64("mem", msg.Resources.Mem).Uint64("memAvailable", msg.Resources.MemAvailable).Msg("monitoring parameters ")
			}
			time.Sleep(1 * time.Second)
		}
	}(routineCtx, stream, newLabs)
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
	ap.Agents[name].Resources.Memory = msg.Resources.Mem
	ap.Agents[name].Resources.MemoryAvailable = msg.Resources.MemAvailable
	ap.Agents[name].Resources.ContainerCount = msg.Resources.ContainerCount
	ap.Agents[name].Resources.VmCount = msg.Resources.VmCount
	ap.Agents[name].Resources.LabCount = msg.Resources.LabCount
	ap.Agents[name].QueuedTasks = msg.QueuedTasks
	ap.M.Unlock()
	//log.Debug().Msg("calculating weights")
	ap.calculateWeights()

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

// Creates a new environment on all available connected agents
func (ap *AgentPool) createNewEnvOnAvailableAgents(ctx context.Context, config EventConfig, estimatedMemUsage uint64) error {
	// Concurrently start environments for event on all available agents
	ap.M.RLock()

	// Check if potential event memory usage will be larger than the total memory available
	if estimatedMemUsage > 0 {
		if float64(estimatedMemUsage) > float64(ap.TotalMemAvailable)*float64(0.9) {
			log.Debug().Msg("to many resources requested from event")
			ap.M.RUnlock()
			return NoResourcesError
		}
	}

	if len(ap.Agents) > 0 {
		var m sync.Mutex
		var wg sync.WaitGroup
		var errs []error
		for agentName, a := range ap.Agents {
			// The initial amount of labs for a specific agent is determined based on the total initial labs needed
			// And the weight calculated for that specific agent
			if _, ok := ap.AgentWeights[agentName]; !ok {
				log.Warn().Str("agent", agentName).Msg("no agent weight calculated for agent")
				errs = append(errs, errors.New("no agent weight calculated for agent"))
				continue
			}
			initialLabs := int32(math.Round(float64(config.InitialLabs) * ap.AgentWeights[agentName]))
			log.Debug().Int32("labs", initialLabs).Str("agent", agentName).Msg("starting env with labs on agent")
			envConfig := aproto.CreatEnvRequest{
				EventTag: config.Tag,
				EnvType:  config.Type,
				// Just temporarily using hardcoded vm config
				Vm: &aproto.VmConfig{
					Image:    config.VmName,
					MemoryMB: 4096,
					Cpu:      0,
				},
				InitialLabs: initialLabs,
				Exercises:   config.ExerciseTags,
				TeamSize:    config.TeamSize,
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
			}(&envConfig, a)
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
func (ap *AgentPool) createLabForEvent(ctx context.Context, isVpn bool, eventTag string) error {
	agentForLab, err := ap.selectAgentForLab()
	if err != nil {
		return errors.New("no suitable agent found")
	}

	client := aproto.NewAgentClient(agentForLab.Conn)

	req := &aproto.CreateLabRequest{
		EventTag: eventTag,
		IsVPN:    isVpn,
	}
	if _, err := client.CreateLabForEnv(ctx, req); err != nil {
		return err
	}

	return nil
}

// Selects the most suitable agent for a lab to be created
// It chooses an agent either based on weight if all agents are idle or depending on the agent which has the least jobs waiting in queue
func (ap *AgentPool) selectAgentForLab() (*Agent, error) {
	ap.M.RLock()
	defer ap.M.RUnlock()

	var weightCandidates []*Agent
	for _, agent := range ap.Agents {
		if agent.QueuedTasks > 0 || agent.StateLock {
			continue
		}
		weightCandidates = append(weightCandidates, agent)
	}

	// If all agents currently have queued tasks
	if len(weightCandidates) == 0 {
		log.Debug().Msg("choosing agent based on amount queued tasks")
		var agentWithLeastTasks *Agent
		first := true
		for _, agent := range ap.Agents {
			if agent.StateLock {
				continue
			}
			if first {
				agentWithLeastTasks = agent
				first = false
				continue
			}
			if agent.QueuedTasks < agentWithLeastTasks.QueuedTasks {
				agentWithLeastTasks = agent
			}
		}
		if agentWithLeastTasks == nil {
			return nil, errors.New("no suitable agent found")
		}
		return agentWithLeastTasks, nil
	}

	// If one or all agents have 0 queued tasks
	// TODO If using weights, CPU should probably also play a role
	log.Debug().Msg("choosing agent based on amount weights")
	var agentWithHigestWeight *Agent
	first := true
	for _, agent := range weightCandidates {
		if agent.StateLock {
			continue
		}
		if first {
			agentWithHigestWeight = agent
			first = false
			continue
		}
		if ap.AgentWeights[agent.Name] > ap.AgentWeights[agentWithHigestWeight.Name] {
			agentWithHigestWeight = agent
		}
	}
	if agentWithHigestWeight == nil {
		return nil, errors.New("no suitable agent found")
	}

	log.Debug().Str("agent", agentWithHigestWeight.Name).Msg("agent with highest weight")
	return agentWithHigestWeight, nil
}

// Calculates initial lab weights based on remaining memory available on each agent
// (Only relevant for beginner type events)
func (ap *AgentPool) calculateWeights() {
	ap.M.Lock()
	defer ap.M.Unlock()
	var totalMemoryAvailable uint64
	var availableAgents []*Agent
	for _, agent := range ap.Agents {
		// Exclude ag
		if agent.StateLock || agent.Resources.Memory > 90 {
			ap.AgentWeights[agent.Name] = 0
			continue
		}
		totalMemoryAvailable += agent.Resources.MemoryAvailable
		availableAgents = append(availableAgents, agent)
	}
	ap.TotalMemAvailable = totalMemoryAvailable
	log.Debug().Uint64("total memory available", ap.TotalMemAvailable).Msg("total memory available")

	for _, agent := range availableAgents {
		if agent.StateLock {
			continue
		}
		weight := float64(agent.Resources.MemoryAvailable) / float64(totalMemoryAvailable)
		if math.IsNaN(weight) || weight <= 0 {
			weight = 0
		}
		ap.AgentWeights[agent.Name] = weight
		log.Debug().Float64("calculated weight", ap.AgentWeights[agent.Name]).Msgf("weight for agent: %s", agent.Name)
	}
}
