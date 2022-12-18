package daemon

func (ep *EventPool) AddEvent(event *Event) {
	ep.M.Lock()
	defer ep.M.Unlock()

	ep.Events[event.Config.Tag] = event
}
