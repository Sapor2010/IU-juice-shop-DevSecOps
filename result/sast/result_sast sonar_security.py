import seaborn as sns
import pandas as pd
import matplotlib.pyplot as plt
from datetime import date, datetime
import matplotlib.dates as mdates
import matplotlib.ticker as ticker

## path to excel file
json_file = "result/sast/sonarqube_response_security.json"


## Styling the Plot and split axes
sns.set_style("whitegrid")
fig, ax = plt.subplots(nrows=1, ncols=1, figsize=(10,5))
fig.patch.set_alpha(0)

############ Step 1 Read excel File 
dat = pd.read_json(json_file)


############ Step 2 format fields into seconds
df = pd.DataFrame(dat)
# Define the columns to count
columns_to_count = ['sonarsource', 'sans_top25', 'owasp_top10', 'cwe']

# Initialize an empty dictionary to store the counts
counts = {col: [] for col in columns_to_count}

# Count occurrences for each severity
for col in columns_to_count:
    for severity in df['severity'].unique():
        count = sum(df[df['severity'] == severity][col].apply(lambda x: len(x)))
        counts[col].append(count)

# Create a new DataFrame with counts and severity
count_df = pd.DataFrame(counts)
count_df['severity'] = df['severity'].unique()

# Melt the DataFrame to prepare for visualization
melted_df = pd.melt(count_df, id_vars='severity', var_name='category', value_name='count')

# Create a barplot using seaborn
ax = sns.barplot(data=melted_df, x='severity', y='count', hue='category')
plt.title('Counts by Severity and Category - Security')
plt.xlabel('Severity')
plt.ylabel('Count')
plt.xticks(rotation=45)
plt.tight_layout()
# label each column
for i in ax.containers:
    ax.bar_label(i,)
## Save result into .svg , .pdf
plt.savefig("result/sast/sonar_count.svg", format='svg')
plt.show()
