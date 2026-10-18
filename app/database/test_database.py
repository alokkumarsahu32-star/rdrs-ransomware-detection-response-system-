from app.database.database import (
    save_event,
    get_total_events,
    get_recent_events
)


print("=" * 50)
print("RDRS DATABASE TEST")
print("=" * 50)


# Save one test event
event = save_event(
    event_type="modified",
    file_path="data/test.txt",
    score=5,
    risk_level="LOW"
)

print(f"Event saved successfully. ID: {event.id}")
print()


# Get total events
total = get_total_events()

print(f"Total Security Events: {total}")
print()


# Get recent events
events = get_recent_events(10)

print("Recent Events:")
print("-" * 50)

for event in events:

    print(
        f"ID: {event.id} | "
        f"Type: {event.event_type} | "
        f"Score: {event.score} | "
        f"Risk: {event.risk_level}"
    )


print("=" * 50)