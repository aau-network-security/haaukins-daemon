package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
)

type State struct {
	EventPool *EventPool `json:"eventPool"`
}

func saveState(eventPool *EventPool, statePath string) error {
	state := State{
		EventPool: eventPool,
	}

	jsonState, err := json.Marshal(state)
	if err != nil {
		log.Error().Err(err).Msg("error marshalling state")
		return err
	}

	path := filepath.Join(statePath, "state.json")
	if err := os.WriteFile(path, jsonState, 0644); err != nil {
		return err
	}

	return nil
}

func resumeState(statePath string) (*EventPool, error) {
	state := State{}

	path := filepath.Join(statePath, "state.json")
	stateStr, err := os.ReadFile(path)
	if stateStr == nil || err != nil {
		return nil, nil
	}

	if err := json.Unmarshal(stateStr, &state); err != nil {
		log.Error().Err(err).Msg("error unmarshalling state")
		if e, ok := err.(*json.SyntaxError); ok {
			log.Printf("syntax error at byte offset %d", e.Offset)
		}
		log.Debug().Msgf("state: %q", stateStr)
		return nil, nil
	}

	for _, event := range state.EventPool.Events {
		event.UnassignedBrowserLabs = make(chan *AgentLab, event.Config.MaxLabs)
		event.TeamsWaitingForBrowserLabs = make(chan *Team)
		event.UnassignedVpnLabs = make(chan *AgentLab, event.Config.MaxLabs)
		event.TeamsWaitingForVpnLabs = make(chan *Team)
		if event.Teams == nil {
			log.Debug().Msgf("event teams is nil")
			event.Teams = make(map[string]*Team)
		}
		if event.Labs == nil {
			event.Labs = make(map[string]*AgentLab)
		}


		// Put unassigned labs into queue for beginner type events
		if EventType(event.Config.Type) == TypeBeginner {
			if len(event.Labs) > len(event.Teams) { // unassigned labs
				assignedLabs := []string{}
				for _, team := range event.Teams {
					if team.Lab != nil {
						assignedLabs = append(assignedLabs, team.Lab.LabInfo.Tag)
					}
				}
			outer:
				for _, lab := range event.Labs {
					for _, labTag := range assignedLabs {
						if lab.LabInfo.Tag == labTag {
							continue outer
						}
					}
					event.UnassignedBrowserLabs <- lab
				}
			}
		}

		event.startQueueHandlers(state.EventPool, statePath)
	}

	log.Debug().Msgf("eventpool after return state: %v", state.EventPool)
	return state.EventPool, nil
}
