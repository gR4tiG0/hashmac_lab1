#!/usr/bin/env python3
from hashlib import blake2b
from random import randbytes
from tqdm import tqdm
from json import dump
import argparse
import logging
import time


logger = None

class CustomFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG: "\033[94m",    # Blue
        logging.INFO: "\033[92m",     # Green
        logging.WARNING: "\033[93m",  # Yellow
        logging.ERROR: "\033[91m",    # Red
        logging.CRITICAL: "\033[95m"  # Magenta
    }
    RESET = "\033[0m"

    FORMATS = {
        logging.DEBUG: "[*] %(message)s",
        logging.INFO: "[+] %(message)s",
        logging.WARNING: "[?] %(message)s",
        logging.ERROR: "[x] %(message)s",
        logging.CRITICAL: "[!] %(message)s"
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        color = self.COLORS.get(record.levelno)
        formatter = logging.Formatter(color + log_fmt + self.RESET)
        return formatter.format(record)
    
def get_logger(logging_level) -> logging.Logger:
    logger = logging.getLogger('lab')
    logger.setLevel(logging_level)

    ch = logging.StreamHandler()
    ch.setLevel(logging_level)
    ch.setFormatter(CustomFormatter())
    logger.addHandler(ch)
    return logger

NAME = "Prikhodko Yuriy Oleksandrovych"
MSG1 = f'Wake up, {NAME}!\nThe Matrix has you...'.encode()
MSG2 = f'Follow the white rabbit.\nKnock, knock, {NAME}.'.encode()

PREIMAGE_BITSIZE = 16
BIRTHDAY_BITSIZE = 32
MUTATION_BYTESIZE = 32

COUNTER_TS = 10000

PREIMAGE_RESFILE = 'data/preimage_results.json'
BIRTHDAY_RESFILE = 'data/birthday_results.json'

def parse_args() -> tuple:
    parser = argparse.ArgumentParser(description="Lab 1")
    parser.add_argument("--log-level", type=str, default="INFO", help="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)") 
    parser.add_argument("--iterations", type=int, default=100, help="Number of iterations")
    args = parser.parse_args()

    log_level = getattr(logging, args.log_level.upper(), None)
    if not isinstance(log_level, int):
        log_level = logging.INFO

    return (log_level, args.iterations)
    

def msgMutator(msg: bytes) -> bytes:
    return randbytes(MUTATION_BYTESIZE//2) + msg + randbytes(MUTATION_BYTESIZE//2)

def preimageAttack(target_hash: bytes, bit_size: int, message: bytes, mutate: bool = False) -> tuple:
    counter = 0
    while True:
        if counter % COUNTER_TS == 0:
            logger.debug(f"Counter: {counter}")
        if mutate:
            new_message = msgMutator(message[16:-16])
        else:
            new_message = message + str(counter).encode()
        new_hash = blake2b(new_message, digest_size=bit_size // 8).digest()
        # new_hash = cutHash(new_hash, bit_size)

        if new_hash == target_hash:
            return (new_message, counter)

        counter += 1

def birthdayAttack(bit_size: int, message: bytes, mutate: bool = False) -> tuple:
    table = {}
    counter = 0
    while True:
        if counter % COUNTER_TS == 0:
            logger.debug(f"Counter: {counter}")
        if mutate:
            new_message = msgMutator(message[16:-16])
        else:
            new_message = message + str(counter).encode()

        new_hash = blake2b(new_message, digest_size=bit_size // 8).digest()
        
        if new_hash in table:
            return (table[new_hash], new_message, counter)
        else:
            table[new_hash] = new_message

        counter += 1

def main() -> None:
    global logger

    log_level, iterations = parse_args()
    logger = get_logger(log_level)

    logger.info(f"Working with preimage attack")
    logger.info(f"Getting with first type of msg generation")
    logger.debug(f"Initial message: {MSG1}")

    logger.info(f"Starting {iterations} iterations")
    time_intervals_v1 = []
    iteration_intervals_v1 = []
    
    for i in tqdm(range(iterations), desc="Iterations"):
        logger.debug(f"Iteration {i}")
        mutated_msg = msgMutator(MSG1)
        logger.debug(f"Mutated message: {mutated_msg}")

        target_hash = blake2b(mutated_msg, digest_size=PREIMAGE_BITSIZE // 8).digest()
        logger.debug(f"Hash: {target_hash.hex()}")

        logger.debug(f"Searching for a preimage with cutted hash")
        start = time.time()
        preimage, counter = preimageAttack(target_hash, PREIMAGE_BITSIZE, mutated_msg)
        stop =  time.time()

        attack_time = stop - start
        time_intervals_v1.append(attack_time)
        iteration_intervals_v1.append(counter)

        logger.debug(f"Preimage found: {preimage} in {attack_time} seconds")
        logger.debug(f"Asserting...")
        new_hash = blake2b(preimage, digest_size=PREIMAGE_BITSIZE // 8).digest()

        assert new_hash == target_hash, f"Preimage is invalid: {new_hash.hex()} != {target_hash.hex()}"
        logger.debug(f"Preimage is valid: {new_hash.hex()} == {target_hash.hex()}")

    logger.debug(f"Obtained time intervals: {time_intervals_v1}")
    logger.debug(f"Obtained iteration intervals: {iteration_intervals_v1}")

    logger.info(f"Average time: {sum(time_intervals_v1) / len(time_intervals_v1)} seconds")
    logger.info(f"Average iterations to complete attack: {sum(iteration_intervals_v1) / len(iteration_intervals_v1)}")

    logger.info(f"Getting with second type of msg generation")

    logger.info(f"Starting {iterations} iterations")
    time_intervals_v2 = []
    iteration_intervals_v2 = []
    
    for i in tqdm(range(iterations), desc="Iterations"):
        logger.debug(f"Iteration {i}")
        mutated_msg = msgMutator(MSG1)
        logger.debug(f"Mutated message: {mutated_msg}")

        target_hash = blake2b(mutated_msg, digest_size=PREIMAGE_BITSIZE // 8).digest()
        logger.debug(f"Hash: {target_hash.hex()}")

        logger.debug(f"Searching for a preimage with obtained hash")
        start = time.time()
        preimage, counter = preimageAttack(target_hash, PREIMAGE_BITSIZE, mutated_msg, mutate=True)
        stop =  time.time()

        attack_time = stop - start
        time_intervals_v2.append(attack_time)
        iteration_intervals_v2.append(counter)

        logger.debug(f"Preimage found: {preimage} in {attack_time} seconds")
        logger.debug(f"Asserting...")
        new_hash = blake2b(preimage, digest_size=PREIMAGE_BITSIZE // 8).digest()

        assert new_hash == target_hash, f"Preimage is invalid: {new_hash.hex()} != {target_hash.hex()}"
        logger.debug(f"Preimage is valid: {new_hash.hex()} == {target_hash.hex()}")

    logger.debug(f"Obtained time intervals: {time_intervals_v2}")
    logger.debug(f"Obtained iteration intervals: {iteration_intervals_v2}")

    logger.info(f"Average time: {sum(time_intervals_v2) / len(time_intervals_v2)} seconds")
    logger.info(f"Average iterations to complete attack: {sum(iteration_intervals_v2) / len(iteration_intervals_v2)}")

    with open(PREIMAGE_RESFILE, 'w') as f:
        dump({"time_intervals_v1": time_intervals_v1, "iteration_intervals_v1": iteration_intervals_v1, "time_intervals_v2": time_intervals_v2, "iteration_intervals_v2": iteration_intervals_v2}, f)


    logger.info(f"-" * 50)

    logger.info(f"Working with birthday attack")
    logger.info(f"Getting with first type of msg generation")
    logger.debug(f"Initial message: {MSG2}")


    logger.info(f"Starting {iterations} iterations")

    time_intervals_v1 = []
    iteration_intervals_v1 = []

    for i in tqdm(range(iterations), desc="Iterations"):
        logger.debug(f"Iteration {i}")
        mutated_msg = msgMutator(MSG2)
        logger.debug(f"Mutated message: {mutated_msg}")
        logger.debug(f"Searching for a collision")

        start = time.time()
        msg1, msg2, counter = birthdayAttack(BIRTHDAY_BITSIZE, mutated_msg)
        stop =  time.time()

        attack_time = stop - start
        time_intervals_v1.append(attack_time)
        iteration_intervals_v1.append(counter)

        logger.debug(f"Collision found: ({msg1}, {msg2}) in {attack_time} seconds")
        logger.debug(f"Asserting...")
        hash1 = blake2b(msg1, digest_size=BIRTHDAY_BITSIZE // 8).digest()
        hash2 = blake2b(msg2, digest_size=BIRTHDAY_BITSIZE // 8).digest()

        assert hash1 == hash2, f"Collision is invalid: {hash1.hex()} != {hash2.hex()}"
        logger.debug(f"Collision is valid: {hash1.hex()} == {hash2.hex()}")
  
    logger.debug(f"Obtained time intervals: {time_intervals_v1}")
    logger.debug(f"Obtained iteration intervals: {iteration_intervals_v1}")

    logger.info(f"Average time: {sum(time_intervals_v1) / len(time_intervals_v1)} seconds")
    logger.info(f"Average iterations to complete attack: {sum(iteration_intervals_v1) / len(iteration_intervals_v1)}")


    logger.info(f"Getting with second type of msg generation")


    logger.info(f"Starting {iterations} iterations")

    time_intervals_v2 = []
    iteration_intervals_v2 = []

    for i in tqdm(range(iterations), desc="Iterations"):
        logger.debug(f"Iteration {i}")
        mutated_msg = msgMutator(MSG2)
        logger.debug(f"Mutated message: {mutated_msg}")
        logger.debug(f"Searching for a collision")

        start = time.time()
        msg1, msg2, counter = birthdayAttack(BIRTHDAY_BITSIZE, mutated_msg, mutate=True)
        stop =  time.time()

        attack_time = stop - start
        time_intervals_v2.append(attack_time)
        iteration_intervals_v2.append(counter)

        logger.debug(f"Collision found: ({msg1}, {msg2}) in {attack_time} seconds")
        logger.debug(f"Asserting...")
        hash1 = blake2b(msg1, digest_size=BIRTHDAY_BITSIZE // 8).digest()
        hash2 = blake2b(msg2, digest_size=BIRTHDAY_BITSIZE // 8).digest()

        assert hash1 == hash2, f"Collision is invalid: {hash1.hex()} != {hash2.hex()}"
        logger.debug(f"Collision is valid: {hash1.hex()} == {hash2.hex()}")
  
    logger.debug(f"Obtained time intervals: {time_intervals_v2}")
    logger.debug(f"Obtained iteration intervals: {iteration_intervals_v2}")

    logger.info(f"Average time: {sum(time_intervals_v2) / len(time_intervals_v2)} seconds")
    logger.info(f"Average iterations to complete attack: {sum(iteration_intervals_v2) / len(iteration_intervals_v2)}")

    with open(BIRTHDAY_RESFILE, 'w') as f:
        dump({"time_intervals_v1": time_intervals_v1, "iteration_intervals_v1": iteration_intervals_v1, "time_intervals_v2": time_intervals_v2, "iteration_intervals_v2": iteration_intervals_v2}, f)

if __name__ == "__main__":
    main()
