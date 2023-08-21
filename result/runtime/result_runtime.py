import seaborn as sns
import pandas as pd
import matplotlib.pyplot as plt
from datetime import date, datetime
import matplotlib.dates as mdates
import matplotlib.ticker as ticker

############ preperation
## path to excel file
excel_file = "result/runtime/summary.xlsx"

## Set a date into time, neccecary for datetime format
my_date = date(2023, 1, 1)

## Styling the Plot and split axes
sns.set_style("whitegrid")
fig, ax = plt.subplots(nrows=1, ncols=1, figsize=(10,5))

############ Step 1 Read excel File 
dat = pd.read_excel(excel_file)


############ Step 2 format fields into seconds
dat['duration'] = pd.to_timedelta(dat['duration'])
# Lint
dat['lint'] = pd.to_timedelta(dat['lint'])
# API Unit Test
dat['API Unit Test (ubuntu-latest, 16)'] = pd.to_timedelta(dat['API Unit Test (ubuntu-latest, 16)'])
dat['API Unit Test (ubuntu-latest, 18)'] = pd.to_timedelta(dat['API Unit Test (ubuntu-latest, 18)'])
dat['API Unit Test (windows-latest, 16)'] = pd.to_timedelta(dat['API Unit Test (windows-latest, 16)'])
dat['API Unit Test (windows-latest, 18)'] = pd.to_timedelta(dat['API Unit Test (windows-latest, 18)'])
# Server Unit Test
dat['Unit Test Server and Frontend (ubuntu-latest, 16)'] = pd.to_timedelta(dat['Unit Test Server and Frontend (ubuntu-latest, 16)'])
dat['Unit Test Server and Frontend (ubuntu-latest, 18)'] = pd.to_timedelta(dat['Unit Test Server and Frontend (ubuntu-latest, 18)'])
dat['Unit Test Server and Frontend (windows-latest, 16)'] = pd.to_timedelta(dat['Unit Test Server and Frontend (windows-latest, 16)'])
dat['Unit Test Server and Frontend (windows-latest, 18)'] = pd.to_timedelta(dat['Unit Test Server and Frontend (windows-latest, 18)'])
# Codeclimate Coverage Report
dat['Codeclimate Coverage Report'] = pd.to_timedelta(dat['Codeclimate Coverage Report'])
# Build npm artefact (ubuntu-latest, 18)
dat['Build npm artefact (ubuntu-latest, 18)'] = pd.to_timedelta(dat['Build npm artefact (ubuntu-latest, 18)'])
# deploy to Azure
dat['deploy to Azure'] = pd.to_timedelta(dat['deploy to Azure'])
# trufflehog
dat['trufflehog'] = pd.to_timedelta(dat['trufflehog'])
# codeql
dat['codeql'] = pd.to_timedelta(dat['codeql'])
# Sonarqube SAST
dat['Sonarqube SAST'] = pd.to_timedelta(dat['Sonarqube SAST'])
# DAST
dat['DAST'] = pd.to_timedelta(dat['DAST'])


############ Step 3 read fields and group them by typ, dividate the seconds_s to hours_h or minutes_m
results_df = pd.DataFrame()

# count by typ DevOps and DevSecOps typ
results_df['count'] = dat.groupby(['typ']).size()
results_df['average_duration'] = dat.groupby(['typ'])['duration'].mean().dt.total_seconds() / 60 

#results_df['average_duration_time'] = [datetime.combine(my_date, t) for t in results_df['average_duration_time']]
results_df['average_linit_m'] = dat.groupby(['typ'])['lint'].mean().dt.total_seconds() / 60 
results_df['average_apiunit_ubuntu16_m'] = dat.groupby(['typ'])['API Unit Test (ubuntu-latest, 16)'].mean().dt.total_seconds() / 60 
results_df['average_apiunit_ubuntu18_m'] = dat.groupby(['typ'])['API Unit Test (ubuntu-latest, 18)'].mean().dt.total_seconds() / 60 
results_df['average_apiunit_windows16_m'] = dat.groupby(['typ'])['API Unit Test (windows-latest, 16)'].mean().dt.total_seconds() / 60 
results_df['average_apiunit_windows18_m'] = dat.groupby(['typ'])['API Unit Test (windows-latest, 18)'].mean().dt.total_seconds() / 60 
results_df['average_unittest_ubuntu16_m'] = dat.groupby(['typ'])['Unit Test Server and Frontend (ubuntu-latest, 16)'].mean().dt.total_seconds() / 60 
results_df['average_unittest_ubuntu18_m'] = dat.groupby(['typ'])['Unit Test Server and Frontend (ubuntu-latest, 18)'].mean().dt.total_seconds() / 60 
results_df['average_unittest_windows16_m'] = dat.groupby(['typ'])['Unit Test Server and Frontend (windows-latest, 16)'].mean().dt.total_seconds() / 60 
results_df['average_unittest_windows18_m'] = dat.groupby(['typ'])['Unit Test Server and Frontend (windows-latest, 18)'].mean().dt.total_seconds() / 60 
results_df['average_cccr_s'] = dat.groupby(['typ'])['Codeclimate Coverage Report'].mean().dt.total_seconds() 
results_df['average_buildnpm_m'] = dat.groupby(['typ'])['Build npm artefact (ubuntu-latest, 18)'].mean().dt.total_seconds() / 60 
results_df['average_deploytoazure_m'] = dat.groupby(['typ'])['deploy to Azure'].mean().dt.total_seconds() / 60 
results_df['average_trufflehog_s'] = dat.groupby(['typ'])['trufflehog'].mean().dt.total_seconds()  
results_df['average_codeql_m'] = dat.groupby(['typ'])['codeql'].mean().dt.total_seconds()  / 60
results_df['average_sq_m'] = dat.groupby(['typ'])['Sonarqube SAST'].mean().dt.total_seconds() / 60 
results_df['average_dast_m'] = dat.groupby(['typ'])['DAST'].mean().dt.total_seconds() / 60 

results_df['average_duration_security'] = results_df['average_trufflehog_s'] + results_df['average_codeql_m'] + results_df['average_sq_m'] + results_df['average_dast_m']


## reset index to have the format
results_df = results_df.reset_index()

## only for debug
print(results_df)


############ Step 4 visualize 
g = sns.barplot(data=results_df, x='typ', y='average_duration')
g = ax.bar_label(ax.containers[0], fmt='%.1f', padding=5)
g = ax.set_title('Average time pipelines Security')
g = ax.set_xlabel('Pipeline type')
g = ax.set_ylabel('Average time in (m)')

## Save result into .svg , .pdf
plt.savefig("result/runtime/avarage_duration_summery.svg", format='svg')

plt.show()


results_df.to_excel('result/runtime/result.xlsx')