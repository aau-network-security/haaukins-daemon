package daemon

import "fmt"

// Adds an event to the event pool
func (ep *EventPool) AddEvent(event *Event) {
	ep.M.Lock()
	defer ep.M.Unlock()

	ep.Events[event.Config.Tag] = event
}

// Removes an event from the event pool
// TODO make sure to close channels
func (ep *EventPool) RemoveEvent(tag string) error {
	ep.M.Lock()
	defer ep.M.Unlock()

	event, ok := ep.Events[tag]
	if !ok {
		return fmt.Errorf("could not find event with tag: %s ", tag)
	}
	close(event.TeamsWaitingForLabs)
	close(event.UnassignedLabs)

	delete(ep.Events, tag)
	return nil
}
