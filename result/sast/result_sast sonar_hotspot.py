import seaborn as sns
import pandas as pd
import matplotlib.pyplot as plt
from datetime import date, datetime
import matplotlib.dates as mdates
import matplotlib.ticker as ticker

## path to excel file
json_file = "result/sast/sonarqube_response_hotspot.json"


## Styling the Plot and split axes
sns.set_style("whitegrid")
fig, ax = plt.subplots(nrows=1, ncols=1, figsize=(10,5))

############ Step 1 Read excel File 
data = pd.read_json(json_file)

# Daten in DataFrame laden
df = pd.DataFrame(data)

## for debug
#print(df)

############ Step 2 Count by sonarsource typ
#  Summe nach Kategorie "severity" und "sonarsource"
df_sum = df.copy()
df_sum['total'] = df_sum['sonarsource'].apply(lambda x: sum(x.values()))


plt.figure(figsize=(10, 5))
ax = sns.barplot(data=df_sum, x='severity', y='total', palette='Set1')
plt.title('SonarQube Security Review Findings')
for i in ax.containers:
    ax.bar_label(i,)
## Save result into .svg , .pdf
plt.savefig("result/sast/sonar_count_hotspot_severiy.svg", format='svg')    
plt.show()

