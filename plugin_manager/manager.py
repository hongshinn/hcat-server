class EventHandle:
    def __init__(self, func, event_class):
        print(event_class.__class__.__base__)
        func()
