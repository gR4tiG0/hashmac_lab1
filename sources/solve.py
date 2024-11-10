#!/usr/bin/env python3
from hashlib import blake2b
from random import choices, randint
from tqdm import tqdm
from json import dump
import argparse
import logging
import time
from string import printable


logger = None
VERBOSE = False

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
MSG1 = f'Wake up, {NAME}!\nThe Matrix has you...'
MSG2 = f'Follow the white rabbit.\nKnock, knock, {NAME}.'

PREIMAGE_BITSIZE = 16
BIRTHDAY_BITSIZE = 32
MUTATION_BYTESIZE = 16

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
    return ''.join(choices(printable, k = MUTATION_BYTESIZE // 2)) + msg + ''.join(choices(printable, k = MUTATION_BYTESIZE // 2))

def msgCorrupt(msg: bytes) -> bytes:
    a = randint(0, len(msg) - 1)
    msg = msg[:a] + choices(printable)[0] + msg[a + 1:]
    return msg

def preimageAttack(target_hash: bytes, bit_size: int, message: bytes, mutate: bool = False, verbose: bool = False) -> tuple:

    if verbose:
        print(f"intial message: {message.encode()}")
        print(f"hash: {target_hash.hex()}")

    counter = 0
    while True:
        if mutate:
            message = msgCorrupt(message)
            new_message = message 
        else:
            new_message = message + str(counter)
        new_hash = blake2b(new_message.encode(), digest_size=bit_size // 8).digest()

        if new_hash == target_hash:
            if verbose: print(f"| {counter} | {new_message.encode()} | {new_hash.hex()} |")
            return (new_message, counter)

        if verbose and counter < 30:
            print(f"| {counter} | {new_message.encode()} | {new_hash.hex()} |")
        else:
            if counter % COUNTER_TS == 0:
                logger.debug(f"Counter: {counter}")

        counter += 1

def birthdayAttack(bit_size: int, message: bytes, mutate: bool = False, verbose: bool = False) -> tuple:
    table = {}
    counter = 0
    if verbose:
        print(f"intial message: {message.encode()}")
    while True:
        
        if mutate:
            message = msgCorrupt(message)
            new_message = message
            logger.debug(f"Corrupted message: {new_message}")
        else:
            new_message = message + str(counter)

        new_hash = blake2b(new_message.encode(), digest_size=bit_size // 8).digest()
        
        if new_hash in table:
            if new_message == table[new_hash]:
                continue
            if verbose: 
                print(f"| {counter} | {new_message.encode()} | {new_hash.hex()} |")
                print(f"{table[new_hash].encode()}, {new_message.encode()}, {list(table.keys()).index(new_hash)}")
            return (table[new_hash], new_message, counter)
        else:
            table[new_hash] = new_message

        if verbose and counter < 30:
            print(f"| {counter} | {new_message.encode()} | {new_hash.hex()} |")
        else:
            if counter % COUNTER_TS == 0:
                logger.debug(f"Counter: {counter}")

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

        target_hash = blake2b(mutated_msg.encode(), digest_size=PREIMAGE_BITSIZE // 8).digest()
        logger.debug(f"Hash: {target_hash.hex()}")

        logger.debug(f"Searching for a preimage with cutted hash")
        start = time.time()
        preimage, counter = preimageAttack(target_hash, PREIMAGE_BITSIZE, mutated_msg, verbose=((i==0)and VERBOSE))
        stop =  time.time()

        attack_time = stop - start
        time_intervals_v1.append(attack_time)
        iteration_intervals_v1.append(counter)

        logger.debug(f"Preimage found: {preimage} in {attack_time} seconds")
        logger.debug(f"Asserting...")
        new_hash = blake2b(preimage.encode(), digest_size=PREIMAGE_BITSIZE // 8).digest()

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

        target_hash = blake2b(mutated_msg.encode(), digest_size=PREIMAGE_BITSIZE // 8).digest()
        logger.debug(f"Hash: {target_hash.hex()}")

        logger.debug(f"Searching for a preimage with obtained hash")
        start = time.time()
        preimage, counter = preimageAttack(target_hash, PREIMAGE_BITSIZE, mutated_msg, mutate=True, verbose=((i==0)and VERBOSE))
        stop =  time.time()

        attack_time = stop - start
        time_intervals_v2.append(attack_time)
        iteration_intervals_v2.append(counter)

        logger.debug(f"Preimage found: {preimage} in {attack_time} seconds")
        logger.debug(f"Asserting...")
        new_hash = blake2b(preimage.encode(), digest_size=PREIMAGE_BITSIZE // 8).digest()

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
        msg1, msg2, counter = birthdayAttack(BIRTHDAY_BITSIZE, mutated_msg, verbose=((i==0)and VERBOSE))
        stop =  time.time()

        attack_time = stop - start
        time_intervals_v1.append(attack_time)
        iteration_intervals_v1.append(counter)

        logger.debug(f"Collision found: ({msg1}, {msg2}) in {attack_time} seconds")
        logger.debug(f"Asserting...")
        hash1 = blake2b(msg1.encode(), digest_size=BIRTHDAY_BITSIZE // 8).digest()
        hash2 = blake2b(msg2.encode(), digest_size=BIRTHDAY_BITSIZE // 8).digest()

        assert hash1 == hash2, f"Collision is invalid: {hash1.hex()} != {hash2.hex()}"
        assert msg1 != msg2
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
        msg1, msg2, counter = birthdayAttack(BIRTHDAY_BITSIZE, mutated_msg, mutate=True, verbose=((i==0)and VERBOSE))
        stop =  time.time()

        attack_time = stop - start
        time_intervals_v2.append(attack_time)
        iteration_intervals_v2.append(counter)

        logger.debug(f"Collision found: ({msg1}, {msg2}) in {attack_time} seconds")
        logger.debug(f"Asserting...")
        hash1 = blake2b(msg1.encode(), digest_size=BIRTHDAY_BITSIZE // 8).digest()
        hash2 = blake2b(msg2.encode(), digest_size=BIRTHDAY_BITSIZE // 8).digest()

        assert hash1 == hash2, f"Collision is invalid: {hash1.hex()} != {hash2.hex()}"
        assert msg1 != msg2
        logger.debug(f"Collision is valid: {hash1.hex()} == {hash2.hex()}")
  
    logger.debug(f"Obtained time intervals: {time_intervals_v2}")
    logger.debug(f"Obtained iteration intervals: {iteration_intervals_v2}")

    logger.info(f"Average time: {sum(time_intervals_v2) / len(time_intervals_v2)} seconds")
    logger.info(f"Average iterations to complete attack: {sum(iteration_intervals_v2) / len(iteration_intervals_v2)}")

    with open(BIRTHDAY_RESFILE, 'w') as f:
        dump({"time_intervals_v1": time_intervals_v1, "iteration_intervals_v1": iteration_intervals_v1, "time_intervals_v2": time_intervals_v2, "iteration_intervals_v2": iteration_intervals_v2}, f)

if __name__ == "__main__":
    main()
