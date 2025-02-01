import pandas as pd

import matplotlib.pyplot as plt

# Read the CSV file
df = pd.read_csv('packet_data_log.csv')

# Create a histogram of data types
plt.figure(figsize=(10, 6))
data_type_counts = df['sizes'].value_counts()
data_type_counts.plot(kind='bar')

# Customize the plot
plt.title('Distribution of Packet Data Types')
plt.xlabel('Data Type')
plt.ylabel('Count')
plt.xticks(rotation=45)
plt.grid(True, alpha=0.3)

# Adjust layout to prevent label cutting
plt.tight_layout()
# Create histogram of packet sizes
plt.figure(figsize=(10, 6))
plt.hist(df['sizes'], bins=50, edgecolor='black')
plt.title('Histogram of Packet Sizes')
plt.xlabel('Packet Size (bytes)')
plt.ylabel('Frequency')
plt.grid(True, alpha=0.3)
plt.tight_layout()

# Save the plot
plt.savefig('packet_data_histogram.png')
plt.show()