from datetime import datetime

from sqlalchemy import text

from app.detector.detector import RansomwareDetector

from app.response.response import quarantine_file

from app.database.database import SessionLocal


class RDRSSystemStatus:

    def __init__(self):

        self.monitor_running = False

        self.monitor_started_at = None

    # ==================================================
    # FILE MONITOR STATUS
    # ==================================================

    def set_monitor_running(self):

        self.monitor_running = True

        self.monitor_started_at = datetime.now()

    def set_monitor_stopped(self):

        self.monitor_running = False

    def is_monitor_running(self):

        return self.monitor_running

    def get_monitor_status(self):

        if self.monitor_running:

            return "ACTIVE"

        return "STOPPED"

    def get_monitor_started_at(self):

        return self.monitor_started_at

    # ==================================================
    # DETECTION ENGINE HEALTH
    # ==================================================

    def check_detection_engine(self):

        try:

            detector = RansomwareDetector()

            if detector is not None:

                return "ACTIVE"

            return "INACTIVE"

        except Exception as error:

            print(
                f"[SYSTEM STATUS] Detection check failed: {error}"
            )

            return "ERROR"

    # ==================================================
    # RESPONSE ENGINE HEALTH
    # ==================================================

    def check_response_engine(self):

        try:

            if callable(quarantine_file):

                return "ACTIVE"

            return "INACTIVE"

        except Exception as error:

            print(
                f"[SYSTEM STATUS] Response check failed: {error}"
            )

            return "ERROR"

    # ==================================================
    # DATABASE HEALTH
    # ==================================================

    def check_database(self):

        db = None

        try:

            db = SessionLocal()

            db.execute(
                text("SELECT 1")
            )

            return "CONNECTED"

        except Exception as error:

            print(
                f"[SYSTEM STATUS] Database check failed: {error}"
            )

            return "ERROR"

        finally:

            if db:

                db.close()

    # ==================================================
    # COMPLETE SYSTEM HEALTH
    # ==================================================

    def get_system_health(self):

        detection_status = (
            self.check_detection_engine()
        )

        response_status = (
            self.check_response_engine()
        )

        database_status = (
            self.check_database()
        )

        monitoring_status = (
            self.get_monitor_status()
        )

        components = [

            detection_status,

            response_status,

            database_status,

            monitoring_status

        ]

        if (

            "ERROR" in components

            or "INACTIVE" in components

            or "STOPPED" in components

        ):

            overall_status = "DEGRADED"

        else:

            overall_status = "OPERATIONAL"

        return {

            "overall_status":
                overall_status,

            "detection_status":
                detection_status,

            "response_status":
                response_status,

            "database_status":
                database_status,

            "monitoring_status":
                monitoring_status

        }


# ==================================================
# GLOBAL SYSTEM STATUS OBJECT
# ==================================================

system_status = RDRSSystemStatus()