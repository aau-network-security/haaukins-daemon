package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	aproto "github.com/aau-network-security/haaukins-agent/pkg/proto"
	"github.com/rs/zerolog/log"
)

var (
	AllAgentsReturnedErr = errors.New("all agents returned error on creating environment")
	NoAgentsConnected    = errors.New("no agents connected")
)

// Send a heartbeat to all agents in the database, remove/add agent if connection status changes
func (ap *AgentPool) connectToMonitoringStream(routineCtx context.Context, newLabs chan aproto.Lab, a *Agent) error {
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
				ap.updateAgentMetrics(a.Name, msg.Resources.Cpu, msg.Resources.Mem, msg.Resources.LabCount, msg.Resources.VmCount, msg.Resources.ContainerCount)
				log.Debug().Str("hb", msg.Hb).Float64("cpu", msg.Resources.Cpu).Float64("mem", msg.Resources.Mem).Uint64("memAvailable", msg.Resources.MemAvailable).Msg("monitoring parameters ")
			}
			time.Sleep(1 * time.Second)
		}
	}(routineCtx, stream, newLabs)
	return nil
}

func (ap *AgentPool) connectToStreams(ctx context.Context, newLabs chan aproto.Lab, a *Agent, eventPool *EventPool) error {
	if err := ap.connectToMonitoringStream(ctx, newLabs, a); err != nil {
		return err
	}
	return nil
}

func (ap *AgentPool) addAgent(agent *Agent) {
	ap.M.Lock()
	defer ap.M.Unlock()

	ap.Agents[agent.Name] = agent
}

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

// TODO updates cpu and mem usage
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

func (ap *AgentPool) updateAgentMetrics(name string, cpu, memory float64, labCount, vmCount, containerCount uint32) (*Agent, error) {
	ap.M.Lock()
	defer ap.M.Unlock()

	_, ok := ap.Agents[name]
	if !ok {
		return nil, fmt.Errorf("no agent found with name: \"%s\" in agentpool", name)
	}

	ap.Agents[name].Resources.Cpu = cpu
	ap.Agents[name].Resources.Memory = memory
	ap.Agents[name].Resources.ContainerCount = containerCount
	ap.Agents[name].Resources.VmCount = vmCount
	ap.Agents[name].Resources.LabCount = labCount

	return ap.Agents[name], nil
}

func (ap *AgentPool) getAgent(name string) (*Agent, error) {
	ap.M.RLock()
	defer ap.M.RUnlock()

	agent, ok := ap.Agents[name]
	if !ok {
		return nil, fmt.Errorf("no agent found with name: \"%s\" in agentpool", name)
	}

	return agent, nil
}

func (ap *AgentPool) createNewEnvOnAvailableAgents(ctx context.Context, config aproto.CreatEnvRequest) error {
	// Concurrently start environments on all available agents
	if len(ap.Agents) > 0 {
		var m sync.Mutex
		var wg sync.WaitGroup
		var errs []error
		for _, a := range ap.Agents {
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
			}(&config, a)
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
