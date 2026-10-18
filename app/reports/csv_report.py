import csv
import os

from app.database.database import get_all_events


REPORT_FOLDER = os.path.abspath(
    "reports"
)


def create_report_folder():

    os.makedirs(
        REPORT_FOLDER,
        exist_ok=True
    )


def generate_security_events_csv():

    create_report_folder()

    report_path = os.path.join(
        REPORT_FOLDER,
        "security_events_report.csv"
    )

    events = get_all_events()

    with open(
        report_path,
        "w",
        newline="",
        encoding="utf-8"
    ) as csv_file:

        writer = csv.writer(
            csv_file
        )

        writer.writerow(
            [
                "ID",
                "Event Type",
                "File Path",
                "Score",
                "Risk Level",
                "Timestamp"
            ]
        )

        for event in events:

            writer.writerow(
                [
                    event.id,
                    event.event_type,
                    event.file_path,
                    event.score,
                    event.risk_level,
                    event.timestamp
                ]
            )

    return report_path