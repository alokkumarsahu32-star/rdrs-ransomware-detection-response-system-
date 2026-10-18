import math


def calculate_entropy(file_path):

    try:

        with open(
            file_path,
            "rb"
        ) as file:

            data = file.read()

        if not data:

            return 0.0

        frequency = [
            0
        ] * 256

        for byte in data:

            frequency[byte] += 1

        entropy = 0.0

        data_length = len(data)

        for count in frequency:

            if count == 0:
                continue

            probability = (
                count / data_length
            )

            entropy -= (
                probability
                * math.log2(probability)
            )

        return round(
            entropy,
            4
        )

    except (
        PermissionError,
        OSError
    ) as error:

        print(
            f"[ENTROPY ERROR] {error}"
        )

        return None