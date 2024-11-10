#!/usr/bin/env python3
import json
import numpy as np
import matplotlib.pyplot as plt
import scipy.stats as stats

def load_data(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data

def calculate_statistics(data):
    mean = np.mean(data)
    variance = np.var(data)
    confidence_interval = stats.norm.interval(0.95, loc=mean, scale=np.std(data) / np.sqrt(len(data)))
    return mean, variance, confidence_interval

def plot_histogram(data, title):
    plt.hist(data, bins=30, color='skyblue', edgecolor='black')
    plt.title(title)
    plt.xlabel('Кількість ітерацій')
    plt.ylabel('Частота')
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.show()

def main() -> None:

    preimage_data = load_data("preimage_results.json")
    birthday_data = load_data("birthday_results.json")

    preimage_data_type1 = np.array(preimage_data['iteration_intervals_v1'])
    preimage_data_type2 = np.array(preimage_data['iteration_intervals_v2'])
    birthday_data_type1 = np.array(birthday_data['iteration_intervals_v1'])
    birthday_data_type2 = np.array(birthday_data['iteration_intervals_v2'])

    preimage_stats_type1 = calculate_statistics(preimage_data_type1)
    preimage_stats_type2 = calculate_statistics(preimage_data_type2)
    birthday_stats_type1 = calculate_statistics(birthday_data_type1)
    birthday_stats_type2 = calculate_statistics(birthday_data_type2)

    print("preimage attack (gen type 1):", preimage_stats_type1)
    print("preimage attack (gen type 2):", preimage_stats_type2)
    print("birthday attack (gen type 1):", birthday_stats_type1)
    print("birthday attack (gen type 2):", birthday_stats_type2)

    plot_histogram(preimage_data_type1, "preimage attack (gen type 1)")
    plot_histogram(preimage_data_type2, "preimage attack (gen type 2)")
    plot_histogram(birthday_data_type1, "birthday attack (gen type 1)")
    plot_histogram(birthday_data_type2, "birthday attack (gen type 2)")

if __name__ == "__main__":
    main()