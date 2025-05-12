import argparse
import os
import math
import logging
import binascii
import mimetypes
from faker import Faker
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command line interface.
    """
    parser = argparse.ArgumentParser(description="Calculates the entropy of files and directories to identify potential sensitive data.")
    parser.add_argument("path", help="Path to the file or directory to analyze.")
    parser.add_argument("-t", "--threshold", type=float, default=4.5, help="Entropy threshold. Files exceeding this value will be flagged. Default: 4.5")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursively analyze directories.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    parser.add_argument("-g", "--generate", action="store_true", help="Generate fake sensitive data for DLP testing.")
    parser.add_argument("-n", "--num-files", type=int, default=10, help="Number of files to generate when using -g. Default: 10")
    parser.add_argument("-d", "--output-dir", type=str, default="fake_data", help="Output directory for generated files. Default: fake_data")

    return parser.parse_args()


def calculate_entropy(data):
    """
    Calculates the Shannon entropy of a byte string.

    Args:
        data (bytes): The data to calculate entropy for.

    Returns:
        float: The entropy of the data.
    """
    if not data:
        return 0

    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy


def analyze_file(filepath, threshold):
    """
    Analyzes a single file and checks if its entropy exceeds the threshold.

    Args:
        filepath (str): The path to the file.
        threshold (float): The entropy threshold.

    Returns:
        bool: True if the file's entropy exceeds the threshold, False otherwise.
    """
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        entropy = calculate_entropy(data)
        logging.debug(f"File: {filepath}, Entropy: {entropy}")
        if entropy > threshold:
            logging.warning(f"File {filepath} exceeds entropy threshold ({threshold}): {entropy}")
            return True
        return False
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return False
    except IOError as e:
        logging.error(f"Error reading file {filepath}: {e}")
        return False


def analyze_directory(dirpath, threshold, recursive=False):
    """
    Analyzes a directory, optionally recursively, and checks the entropy of each file.

    Args:
        dirpath (str): The path to the directory.
        threshold (float): The entropy threshold.
        recursive (bool): Whether to analyze the directory recursively.
    """
    try:
        for entry in os.scandir(dirpath):
            if entry.is_file():
                analyze_file(entry.path, threshold)
            elif entry.is_dir() and recursive:
                analyze_directory(entry.path, threshold, recursive)
    except FileNotFoundError:
        logging.error(f"Directory not found: {dirpath}")
    except OSError as e:
        logging.error(f"Error scanning directory {dirpath}: {e}")


def generate_fake_sensitive_data(num_files, output_dir):
    """
    Generates fake sensitive data files for DLP testing.

    Args:
        num_files (int): The number of files to generate.
        output_dir (str): The directory to save the files to.
    """
    fake = Faker()

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    for i in range(num_files):
        filename = os.path.join(output_dir, f"fake_sensitive_data_{i}.txt")
        try:
            with open(filename, "w") as f:
                # Generate various types of sensitive data
                f.write(f"Name: {fake.name()}\n")
                f.write(f"Address: {fake.address()}\n")
                f.write(f"Credit Card Number: {fake.credit_card_number()}\n")
                f.write(f"SSN: {fake.ssn()}\n")
                f.write(f"Email: {fake.email()}\n")
                f.write(f"Phone Number: {fake.phone_number()}\n")
                f.write(f"Company: {fake.company()}\n")
                f.write(f"IP Address: {fake.ipv4()}\n")
                f.write(f"Date of Birth: {fake.date_of_birth().strftime('%Y-%m-%d')}\n")
                f.write(f"License Plate: {fake.license_plate()}\n")


            logging.info(f"Generated fake sensitive data file: {filename}")
        except IOError as e:
            logging.error(f"Error writing to file {filename}: {e}")



def main():
    """
    Main function to parse arguments and run the analysis or data generation.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.generate:
        generate_fake_sensitive_data(args.num_files, args.output_dir)
    else:
        path = args.path
        threshold = args.threshold
        recursive = args.recursive

        if os.path.isfile(path):
            analyze_file(path, threshold)
        elif os.path.isdir(path):
            analyze_directory(path, threshold, recursive)
        else:
            logging.error(f"Path not found: {path}")


if __name__ == "__main__":
    main()


# Usage Examples:

# 1. Analyze a single file:
# python dlpa_SensitiveDataEntropyAnalyzer.py my_document.txt

# 2. Analyze a directory recursively with a custom threshold:
# python dlpa_SensitiveDataEntropyAnalyzer.py /path/to/directory -r -t 5.0

# 3. Generate 20 fake sensitive data files in a directory named "test_data":
# python dlpa_SensitiveDataEntropyAnalyzer.py -g -n 20 -d test_data

# 4. Enable verbose logging:
# python dlpa_SensitiveDataEntropyAnalyzer.py my_document.txt -v