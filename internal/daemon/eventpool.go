package daemon

import (
	"fmt"

	"github.com/rs/zerolog/log"
)

// Adds an event to the event pool
func (ep *EventPool) AddEvent(event *Event) {
	ep.M.Lock()
	defer ep.M.Unlock()

	ep.Events[event.Config.Tag] = event
}

// Removes an event from the event pool
// TODO make sure to close channels
func (ep *EventPool) RemoveEvent(eventTag string) error {
	ep.M.Lock()
	defer ep.M.Unlock()

	event, ok := ep.Events[eventTag]
	if !ok {
		return fmt.Errorf("could not find event with tag: %s ", eventTag)
	}
	close(event.TeamsWaitingForBrowserLabs)
	close(event.TeamsWaitingForVpnLabs)
	close(event.UnassignedBrowserLabs)
	close(event.UnassignedVpnLabs)

	delete(ep.Events, eventTag)
	return nil
}

func (ep *EventPool) GetEvent(eventTag string) (*Event, error) {
	ep.M.RLock()
	defer ep.M.RUnlock()

	event, ok := ep.Events[eventTag]
	if !ok {
		return nil, fmt.Errorf("could not find event with tag: %s ", eventTag)
	}

	return event, nil
}

// Event
func (event *Event) GetTeam(username string) (*Team, error) {
	event.M.RLock()
	defer event.M.RUnlock()

	team, ok := event.Teams[username]
	if !ok {
		return nil, fmt.Errorf("could not find team with username: %s ", username)
	}

	return team, nil
}

func (event *Event) AddTeam(team *Team) {
	event.M.Lock()
	defer event.M.Unlock()

	event.Teams[team.Username] = team
}

// The queue handlers are pulling out teams waiting for labs from one channel
// Then waits for a lab to become available
// When a labs enters the unassigned lab queue, it will assign the lab to the team previously pulled
// Relies heavily on the blocking functionality of channels
func (event *Event) startQueueHandlers() {
	browserQueueHandler := func() {
		for {
			log.Debug().Msg("Waiting for teams to enter browser lab queue")
			team, ok := <-event.TeamsWaitingForBrowserLabs
			if ok {
				log.Debug().Msgf("pulled team from browser queue: %v", team)
			} else {
				log.Debug().Msg("channel closed closing browserQueueHandler")
				return
			}
			team.M.Lock()
			team.Status = WaitingForLab
			team.M.Unlock()

			// TODO Make agent send return even if it fails to create the lab
			// TODO Make unblocking and implement cancel
			lab, ok := <-event.UnassignedBrowserLabs
			if ok {
				log.Debug().Msgf("pulled lab from browser queue: %v", lab)
			} else {
				log.Debug().Msg("channel closed closing browserQueueHandler")
				return
			}

			team.M.Lock()
			team.Lab = lab
			team.Status = Idle
			team.M.Unlock()
			// TODO Assign labs but first implement correct object to be sent between agent and daemon
		}
	}

	vpnQueueHandler := func() {
		for {
			log.Debug().Msg("Waiting for team to enter vpn lab queue")

			team, ok := <-event.TeamsWaitingForVpnLabs
			if ok {
				log.Debug().Msgf("pulled team from vpn queue: %v", team)
			} else {
				log.Debug().Msg("channel closed closing vpnQueueHandler")
				return
			}
			team.M.Lock()
			team.Status = WaitingForLab
			team.M.Unlock()

			lab, ok := <-event.UnassignedVpnLabs
			if ok {
				log.Debug().Msgf("pulled lab from vpn queue: %v", lab)
			} else {
				log.Debug().Msg("channel closed closing vpnQueueHandler")
				return
			}

			team.M.Lock()
			team.Lab = lab
			team.Status = Idle
			team.M.Unlock()
			// TODO Assign labs but first implement correct object to be sent between agent and daemon

		}
	}

	go browserQueueHandler()

	go vpnQueueHandler()
}

// Team

func (team *Team) AddLab(lab *AgentLab) error {
	team.M.Lock()
	defer team.M.Unlock()

	team.Lab = lab
	return nil
}
