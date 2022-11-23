package agent

import (
	"context"
	"fmt"

	aproto "github.com/aau-network-security/haaukins-agent/pkg/proto"
	"github.com/rs/zerolog/log"
)

// Send a heartbeat to all agents in the database, remove/add agent if connection status changes
func (a *AgentPool) heartbeatRutine() {
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
	delete(ap.Agents, name)

	return nil
}

func (ap *AgentPool) updateAgent() {

}

func (a *Agent) ConnectToStreams(ctx context.Context, newLabs chan aproto.Lab) error {
	if err := a.connectToLabStream(ctx, newLabs); err != nil {

	}

	return nil
}

func (a *Agent) connectToLabStream(routineCtx context.Context, newLabs chan aproto.Lab) error {
	ctx := context.Background()
	stream, err := a.Client.LabStream(ctx, &aproto.Empty{})
	if err != nil {
		return fmt.Errorf("error connecting to labStream: %v", err)
	}

	go func(ctx context.Context, newLabs chan aproto.Lab) {
		for {
			select {
			case <-ctx.Done():
				log.Debug().Str("agentName", a.Name).Msg("agent was signaled to close connections")
				if err := stream.CloseSend(); err != nil {
					log.Error().Err(err).Msg("error calling CloseSend()")
				}
				return
			default:
				log.Debug().Msg("Checking for incoming newLabs")
				// newLab, err := stream.Recv()
				// if err != nil {
				// 	log.Error().Err(err).Msg("error recieving new labs")
				// }
				// log.Debug().Msgf("newLab: %v", newLab)
			}
		}
	}(routineCtx, newLabs)
	return nil
}
