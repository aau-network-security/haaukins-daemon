package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	aproto "github.com/aau-network-security/haaukins-agent/pkg/proto"
	"github.com/rs/zerolog/log"
)
type EventType uint8
const (
	// LabType
	TypeBeginner EventType = iota
	TypeAdvanced
)

var (
	AllAgentsReturnedErr = errors.New("all agents returned error on creating environment")
	NoAgentsConnected    = errors.New("no agents connected")
)

// Send a heartbeat to all agents in the database, remove/add agent if connection status changes
func (ap *AgentPool) connectToMonitoringStream(routineCtx context.Context, newLabs chan aproto.Lab, a *Agent, eventPool *EventPool) error {
	client := aproto.NewAgentClient(a.Conn)
	stream, err := client.MonitorStream(routineCtx)
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
				// TODO: Do something with the new labs, hmm how do i access eventpool without import cycle errors
				for _, l := range msg.NewLabs {
					log.Debug().Str("lab-tag", l.Tag).Msg("recieved lab from agent")
				}
				ap.updateAgentMetrics(a.Name, msg.Resources.Cpu, msg.Resources.Mem, msg.Resources.LabCount, msg.Resources.VmCount, msg.Resources.ContainerCount, msg.Resources.MemAvailable)
				//log.Debug().Str("hb", msg.Hb).Float64("cpu", msg.Resources.Cpu).Float64("mem", msg.Resources.Mem).Uint64("memAvailable", msg.Resources.MemAvailable).Msg("monitoring parameters ")
			}
			time.Sleep(1 * time.Second)
		}
	}(routineCtx, stream, newLabs)
	return nil
}

// Connects the daemon to an agent's streams (monitoring etc.)
func (ap *AgentPool) connectToStreams(ctx context.Context, newLabs chan aproto.Lab, a *Agent, eventPool *EventPool) error {
	if err := ap.connectToMonitoringStream(ctx, newLabs, a, eventPool); err != nil {
		return err
	}
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
func (ap *AgentPool) updateAgentMetrics(name string, cpu, memory float64, labCount, vmCount, containerCount uint32, memoryAvailable uint64) (*Agent, error) {
	ap.M.Lock()

	_, ok := ap.Agents[name]
	if !ok {
		return nil, fmt.Errorf("no agent found with name: \"%s\" in agentpool", name)
	}

	ap.Agents[name].Resources.Cpu = cpu
	ap.Agents[name].Resources.Memory = memory
	ap.Agents[name].Resources.MemoryAvailable = memoryAvailable
	ap.Agents[name].Resources.ContainerCount = containerCount
	ap.Agents[name].Resources.VmCount = vmCount
	ap.Agents[name].Resources.LabCount = labCount
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
func (ap *AgentPool) createNewEnvOnAvailableAgents(ctx context.Context, config EventConfig) error {
	// Concurrently start environments for event on all available agents
	if len(ap.Agents) > 0 {
		var m sync.Mutex
		var wg sync.WaitGroup
		var errs []error
		for agentName, a := range ap.Agents {
			// The initial amount of labs for a specific agent is determined based on the total initial labs needed
			// And the weight calculated for that specific agent
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
		wg.Wait()

		if len(errs) == len(ap.Agents) {
			return AllAgentsReturnedErr
		}
	} else {
		return NoAgentsConnected
	}
	return nil
}

// Calculates initial lab weights based on remaining memory available on each agent
// (Only relevant for beginner type events)
func (ap *AgentPool) calculateWeights() {
	ap.M.Lock()
	defer ap.M.Unlock()
	var totalMemoryAvailable uint64
	for _, agent := range ap.Agents {
		if agent.StateLock {
			continue
		}
		totalMemoryAvailable += agent.Resources.MemoryAvailable
	}
	for agentName, agent := range ap.Agents {
		if agent.StateLock {
			continue
		}
		ap.AgentWeights[agentName] = float64(agent.Resources.MemoryAvailable) / float64(totalMemoryAvailable)
		//log.Debug().Float64("calculated weight", ap.AgentWeights[agentName]).Msgf("weight for agent: %s", agentName)
	}
}
