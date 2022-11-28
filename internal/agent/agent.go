package agent

import (
	"context"
	"fmt"
	"io"
	"time"

	aproto "github.com/aau-network-security/haaukins-agent/pkg/proto"
	"github.com/rs/zerolog/log"
)

// Send a heartbeat to all agents in the database, remove/add agent if connection status changes
func (a *Agent) connectToMonitoringStream(routineCtx context.Context, newLabs chan aproto.Lab) error {
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
						return
					}
					continue
				}
				msg, err := stream.Recv()
				if err != nil {
					log.Error().Err(err).Msg("error recieving new labs")
					if err == io.EOF {
						return
					}
					continue
				}
				// TODO: Do something with the new labs
				for _, l := range msg.NewLabs {
					log.Debug().Str("lab-tag", l.Tag).Msg("recieved lab from agent")
				}
				log.Debug().Str("hb", msg.Hb).Float64("cpu", msg.Cpu).Float64("mem", msg.Mem).Uint64("memAvailable", msg.MemAvailable).Msg("monitoring parameters ")
			}
			time.Sleep(1 * time.Second)
		}
	}(routineCtx, stream, newLabs)
	return nil
}

func (a *Agent) ConnectToStreams(ctx context.Context, newLabs chan aproto.Lab) error {
	if err := a.connectToMonitoringStream(ctx, newLabs); err != nil {
		return err
	}
	return nil
}

func (ap *AgentPool) AddAgent(agent *Agent) {
	ap.M.Lock()
	defer ap.M.Unlock()

	ap.Agents[agent.Name] = agent
}

func (ap *AgentPool) RemoveAgent(name string) error {
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
func (ap *AgentPool) UpdateAgentState(name string, lock bool) error {
	ap.M.Lock()
	defer ap.M.Unlock()

	_, ok := ap.Agents[name]
	if !ok {
		return fmt.Errorf("no agent found with name: \"%s\" in agentpool",name)
	}

	ap.Agents[name].StateLock = lock
	return nil
}

func (ap *AgentPool) GetAgent(name string) (*Agent, error) {
	ap.M.RLock()
	defer ap.M.RUnlock()

	agent, ok := ap.Agents[name]
	if !ok {
		return nil, fmt.Errorf("no agent found with name: \"%s\" in agentpool", name)
	}

	return agent, nil
}




