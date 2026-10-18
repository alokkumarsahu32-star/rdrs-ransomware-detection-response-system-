from app.detector.detector import RansomwareDetector


print("=" * 60)
print("RDRS BEHAVIORAL DETECTOR TEST")
print("=" * 60)


# --------------------------------------------------
# TEST 1: NORMAL MODIFICATION ACTIVITY
# --------------------------------------------------

print()
print("[TEST 1] Modification Activity")
print("-" * 60)

detector = RansomwareDetector()

for i in range(1, 11):

    result = detector.record_event(
        "modified",
        f"test_file_{i}.txt"
    )

    print(
        f"Modification {i:02d} -> "
        f"Score: {result['score']} | "
        f"Risk: {result['risk']} | "
        f"Suspicious: {result['suspicious']}"
    )


# --------------------------------------------------
# TEST 2: DELETION ACTIVITY
# --------------------------------------------------

print()
print("[TEST 2] File Deletion Activity")
print("-" * 60)

detector = RansomwareDetector()

for i in range(1, 4):

    result = detector.record_event(
        "deleted",
        f"deleted_file_{i}.txt"
    )

    print(
        f"Deletion {i} -> "
        f"Score: {result['score']} | "
        f"Risk: {result['risk']} | "
        f"Suspicious: {result['suspicious']}"
    )


# --------------------------------------------------
# TEST 3: RENAME / MOVE ACTIVITY
# --------------------------------------------------

print()
print("[TEST 3] Rename / Move Activity")
print("-" * 60)

detector = RansomwareDetector()

for i in range(1, 4):

    result = detector.record_event(
        "moved",
        f"renamed_file_{i}.txt"
    )

    print(
        f"Rename {i} -> "
        f"Score: {result['score']} | "
        f"Risk: {result['risk']} | "
        f"Suspicious: {result['suspicious']}"
    )


# --------------------------------------------------
# TEST 4: SUSPICIOUS EXTENSION
# --------------------------------------------------

print()
print("[TEST 4] Suspicious File Extension")
print("-" * 60)

detector = RansomwareDetector()

suspicious_files = [
    "document.crypt",
    "photo.encrypted",
    "database.locked"
]

for file_name in suspicious_files:

    result = detector.record_event(
        "modified",
        file_name
    )

    print(
        f"{file_name} -> "
        f"Score: {result['score']} | "
        f"Risk: {result['risk']} | "
        f"Suspicious: {result['suspicious']}"
    )


# --------------------------------------------------
# TEST 5: COMBINED RANSOMWARE-LIKE BEHAVIOR
# --------------------------------------------------

print()
print("[TEST 5] Combined Ransomware-like Activity")
print("-" * 60)

detector = RansomwareDetector()

events = [
    ("modified", "document1.txt"),
    ("modified", "document2.txt"),
    ("modified", "document3.txt"),
    ("modified", "document4.txt"),
    ("modified", "document5.txt"),
    ("modified", "document6.txt"),
    ("modified", "document7.txt"),
    ("moved", "document8.crypt"),
    ("deleted", "document9.txt"),
]

for event_type, file_name in events:

    result = detector.record_event(
        event_type,
        file_name
    )

    print(
        f"{event_type.upper():8} {file_name:25} -> "
        f"Score: {result['score']:02d} | "
        f"Risk: {result['risk']:6} | "
        f"Suspicious: {result['suspicious']}"
    )


print()
print("=" * 60)
print("ALL DETECTOR TESTS COMPLETED")
print("=" * 60)