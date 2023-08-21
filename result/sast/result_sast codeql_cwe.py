import seaborn as sns
import pandas as pd
import matplotlib.pyplot as plt


## path to json file
json_file = "result/sast/response.json"

## Styling the Plot and split axes
sns.set_style("whitegrid")
fig, ax = plt.subplots(nrows=1, ncols=1, figsize=(17,7))
############ Step 1 Read json File 
dat = pd.read_json(json_file)

############ Step 2 read rule field and count by security level
# Create a DataFrame from the JSON data
df = pd.DataFrame(dat)

# Extract severity and tags from the rule column
df['severity'] = df['rule'].apply(lambda x: x['severity'])
df['tags'] = df['rule'].apply(lambda x: x['tags'])

# Convert the tags list into a comma-separated string
df['tags'] = df['tags'].apply(lambda x: ', '.join(x))

# Group by severity and tags and count the occurrences
grouped_df = df.groupby(['severity', 'tags']).size().reset_index(name='count')

## only for debug
print(grouped_df)
grouped_df.to_excel('result/sast/result_codeql_cwe.xlsx')

# Create a barplot using seaborn
plt.figure(figsize=(17, 7))
ax = sns.barplot(data=grouped_df, x='count', y='severity', hue='tags',orient='h',errwidth=0)
plt.title('Severity vs Tags Count')
plt.xlabel('Count')
plt.ylabel('Severity')
plt.xticks(rotation=45)
plt.tight_layout()
# label each column
for i in ax.containers:
    ax.bar_label(i,)

## Save result into .svg , .pdf
plt.savefig("result/sast/codeql_countsecuritylevel_cwe.svg", format='svg')   
# Show the plot
plt.show()

