from collections import deque
import os
import time

from app.detector.entropy import calculate_entropy
from app.detector.process_info import get_process_metadata


class RansomwareDetector:

    def __init__(
        self,
        time_window=5,
        threshold=10
    ):

        self.time_window = time_window
        self.threshold = threshold

        self.events = deque()

    def record_event(
        self,
        event_type,
        file_path
    ):

        current_time = time.time()

        file_path = os.path.abspath(
            file_path
        )

        self.events.append(
            (
                current_time,
                event_type,
                file_path
            )
        )

        while (
            self.events
            and
            current_time - self.events[0][0]
            > self.time_window
        ):

            self.events.popleft()

        return self.check_suspicious_activity()

    def check_suspicious_activity(self):

        modifications = sum(
            1
            for _, event, _
            in self.events
            if event == "modified"
        )

        deletions = sum(
            1
            for _, event, _
            in self.events
            if event == "deleted"
        )

        renames = sum(
            1
            for _, event, _
            in self.events
            if event == "moved"
        )

        created_files = sum(
            1
            for _, event, _
            in self.events
            if event == "created"
        )

        # ==================================================
        # SHANNON ENTROPY ANALYSIS
        # ==================================================

        entropy = None

        for _, _, file_path in reversed(
            self.events
        ):

            if os.path.isfile(file_path):

                entropy = calculate_entropy(
                    file_path
                )

                break

        # ==================================================
        # PROCESS METADATA
        # ==================================================

        process_metadata = (
            get_process_metadata()
        )

        # ==================================================
        # EXISTING BEHAVIORAL SCORING
        # ==================================================

        modification_score = min(
            modifications,
            10
        )

        deletion_score = (
            deletions * 2
        )

        rename_score = (
            renames * 3
        )

        activity_score = (
            modification_score
            + deletion_score
            + rename_score
        )

        # ==================================================
        # SUSPICIOUS EXTENSION DETECTION
        # ==================================================

        suspicious_extensions = 0

        for _, _, file_path in self.events:

            extension = os.path.splitext(
                file_path
            )[1].lower()

            if extension in {
                ".encrypted",
                ".enc",
                ".locked",
                ".crypt",
                ".ransom",
                ".wncry",
                ".lockbit"
            }:

                suspicious_extensions += 5

        # ==================================================
        # ENTROPY SCORE
        # ==================================================

        entropy_score = 0

        if entropy is not None:

            if entropy >= 7.5:

                entropy_score = 4

            elif entropy >= 7.0:

                entropy_score = 2

        # ==================================================
        # FINAL SCORE
        # ==================================================

        score = (
            activity_score
            + suspicious_extensions
            + entropy_score
        )

        # ==================================================
        # RISK LEVEL
        # ==================================================

        if score >= 15:

            risk = "HIGH"

        elif score >= 10:

            risk = "MEDIUM"

        elif score >= 5:

            risk = "LOW"

        else:

            risk = "NORMAL"

        suspicious = (
            score >= self.threshold
        )

        # ==================================================
        # REASON
        # ==================================================

        reason = self.get_reason(
            modifications,
            deletions,
            renames,
            suspicious_extensions,
            created_files,
            entropy,
            entropy_score
        )

        # ==================================================
        # RESULT
        # ==================================================

        return {

            "suspicious":
                suspicious,

            "score":
                score,

            "risk":
                risk,

            "reason":
                reason,

            "entropy":
                entropy,

            "process":
                process_metadata
        }

    def get_reason(
        self,
        modifications,
        deletions,
        renames,
        suspicious_extensions,
        created_files,
        entropy,
        entropy_score
    ):

        reasons = []

        if modifications > 0:

            reasons.append(
                "Rapid file modification activity"
            )

        if deletions > 0:

            reasons.append(
                "File deletion activity"
            )

        if renames > 0:

            reasons.append(
                "File rename activity"
            )

        if suspicious_extensions > 0:

            reasons.append(
                "Suspicious file extension detected"
            )

        if entropy_score > 0:

            reasons.append(
                "High file entropy detected"
            )

        if not reasons:

            return "Normal file activity"

        return "; ".join(
            reasons
        )