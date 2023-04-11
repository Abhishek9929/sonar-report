from jinja2 import Environment, PackageLoader
import os
import requests
import json
import sys
import datetime
import pdfkit
import operator

time = datetime.datetime.now()
current_date = time.strftime("%Y") + "-" + time.strftime("%m") + "-" + time.strftime("%d")
current_date_time = current_date_time = time.strftime("%Y") + "_" + time.strftime("%m") + "_" + time.strftime("%d") + "-" + time.strftime("%X")

sonarqube_server_url = sys.argv[1]
sonarqube_server_port = sys.argv[2]
sonarqube_admin_username = sys.argv[3]
sonarqube_admin_password = sys.argv[4]
sonarqube_analysis_project_name = sys.argv[5]

sonarqube_url = "http://" + sonarqube_server_url + ":" + sonarqube_server_port

env = Environment(loader=PackageLoader('app'), autoescape=True)
template = env.get_template('index.html')
 
root = os.path.dirname(os.path.abspath(__file__))
filename = os.path.join(root, 'html', '{}.html'.format(sonarqube_analysis_project_name))

ruleID = {
		"java" : ["squid:S138","squid:S00104"],
		"py" : ["python:S104"],
		"ts" : ["squid:S138","typescript:S104"],
		"js" : ["javascript:S138"],
		"php" : ["php:S2042","php:S138"],
		"web" : []
	}

def getProjectKey(name):
	try:
		req = requests.get("{}/api/projects/index".format( sonarqube_url), 
					auth=( sonarqube_admin_username,  sonarqube_admin_password))
		res = json.loads(req.content)

		for project in res:
			if project['nm'] == name:
				project_key = project['k']
				return project_key	
	except:
		raise Exception("Unable to login, check username, password or URL")


def getComponentID(key):
	try:
		req = requests.get("{}/api/components/show?key={}".format( sonarqube_url, key),
					auth=( sonarqube_admin_username,  sonarqube_admin_password))
		res = json.loads(req.content)
		return res['component']['id']
	except:
		raise Exception("No such project of name {}".format(sonarqube_analysis_project_name))

	
def getLeakPeriodDate(key):
	try:	
		req = requests.get("{}/api/components/show?key={}".format( sonarqube_url,key),
					auth=( sonarqube_admin_username,  sonarqube_admin_password))
		res = json.loads(req.content)
		return res['component']['leakPeriodDate'].split(":")[0].split("T")[0]
	except:
		raise Exception("Unable to find Leak Period Date")

def getLastAnalysisDate(key):
        try:
                req = requests.get("{}/api/components/show?key={}".format( sonarqube_url,key),
                                        auth=( sonarqube_admin_username,  sonarqube_admin_password))
                res = json.loads(req.content)
                return res['component']['analysisDate'].split(":")[0].split("T")[0]
        except:
                raise Exception("Unable to find last analysis Date")


def getMetricResult(metric,component_id):
	try:
		req = requests.get("{}/api/measures/component?metricKeys={}&componentId={}".format( sonarqube_url,metric,component_id),
					auth=( sonarqube_admin_username,  sonarqube_admin_password))
		res = json.loads(req.content)
		# print(res)
		if metric == "sqale_index":
			return(int(res['component']['measures'][0]['value'])/60/8 + 1)
		return res['component']['measures'][0]['value']
	except:
		raise Exception("Unable to find metric : {}".format(metric))


def getLeakPeriodMetricResult(metric,component_id):
	try:
		req = requests.get("{}/api/measures/component?metricKeys={}&componentId={}".format( sonarqube_url,metric,component_id),
					auth=( sonarqube_admin_username,  sonarqube_admin_password))
		res = json.loads(req.content)

		if metric == "new_technical_debt":
			return(int(res['component']['measures'][0]['periods'][0]['value'])/60/8 + 1)
		return res['component']['measures'][0]['periods'][0]['value']
	except:
		raise Exception("Unable to find metric : {}".format(metric))

def getIssueCount(issue_type,project_key):
        try:
                req = requests.get("{}/api/issues/search?severities={}&statuses=OPEN,REOPENED&projectKeys={}&pageSize=-1".format(sonarqube_url, issue_type, project_key),
                                        auth=(sonarqube_admin_username, sonarqube_admin_password))
                res = json.loads(req.content)
		# print(res)
                count = res['paging']['total']
                # for issue in range(len(res['issues'])):
                #         if res['issues'][issue]['status'] == "OPEN"  or res['issues'][issue]['status'] == "REOPENED":
                #                 count += 1
                return count
        except:
                raise Exception("Unable to find count of {}".format(issue_type))

def getLanguage(component_id):
	try:
		req = requests.get("{}/api/measures/component?metricKeys=ncloc_language_distribution&componentId={}".format( sonarqube_url,component_id),
					auth=( sonarqube_admin_username,  sonarqube_admin_password))
		res = json.loads(req.content)
		nloc = res['component']['measures'][0]['value'].split(";")
		nloc_language = {}
		for i in nloc:
			nloc_language.update({i.split("=")[0] : int(i.split("=")[1])})
		language = max(nloc_language, key=nloc_language.get)
		return(language)
	except:
		raise Exception("Unable to find language")


def getBugsByRules(language,key,ruleID):
	bugsByRules = {}
	name = {}
	for rule in ruleID[language]:
		issues_breaking_function_length_rule = requests.get("{}/api/issues/search?rules={}&ps=200&projectKeys={}".format(sonarqube_url,rule,key), auth=(sonarqube_admin_username, sonarqube_admin_password))
		res = json.loads(issues_breaking_function_length_rule.content)
		bugs = []
		for issue in range(len(res['issues'])):
			if res['issues'][issue]['status'] == "OPEN" or res['issues'][issue]['status'] == "REOPENED":
				if rule.split(":")[1] == "S138":
					if language == "php":
						bug = {
							"message" : res['issues'][issue]['message'],
							"component" : res['issues'][issue]['component'],
							"line" : res['issues'][issue]['line'],
							"method_line_count" : int(res['issues'][issue]['message'].split(" ")[4].replace(",",""))
						}
						bugs.append(bug)
						bugs = sorted(bugs, key=lambda i: i['method_line_count'], reverse=True)
					else:
						bug = {
							"message" : res['issues'][issue]['message'],
							"component" : res['issues'][issue]['component'],
							"line" : res['issues'][issue]['line'],
							"method_line_count" : int(res['issues'][issue]['message'].split(" ")[3].replace(",",""))
						}
						bugs.append(bug)
						bugs = sorted(bugs, key=lambda i: i['method_line_count'], reverse=True)
				else:
					bug = {
						"message" : res['issues'][issue]['message'],
						"component" : res['issues'][issue]['component'],
						"line_count" : int(res['issues'][issue]['message'].split(" ")[3].replace(",",""))
					}
					bugs.append(bug)
					bugs = sorted(bugs, key=lambda i: i['line_count'], reverse=True)
		bugsByRules.update({rule:bugs})

	for rule in ruleID[language]:
		names = requests.get("{}/api/rules/show?key={}".format(sonarqube_url,rule), auth=(sonarqube_admin_username, sonarqube_admin_password))
		res = json.loads(names.content)
		name.update({rule:res['rule']['name']})

	return bugsByRules, name


def getbugCountByRule(language,key,ruleID):
	count = 0
	bugCountByRules = {}
	for rule in ruleID[language]:
		issues_breaking_function_length_rule = requests.get("{}/api/issues/search?rules={}&ps=200&projectKeys={}".format(sonarqube_url,rule,key), auth=(sonarqube_admin_username, sonarqube_admin_password))
		res = json.loads(issues_breaking_function_length_rule.content)
		for issue in range(len(res['issues'])):
			if res['issues'][issue]['status'] == "OPEN" or res['issues'][issue]['status'] == "REOPENED":
				count += 1
		bugCountByRules.update({rule:count})
	return bugCountByRules


def getBugList(key):
	try:
		req = requests.get("{}/api/issues/search?types=BUG&projectKeys={}".format(sonarqube_url,key),
					auth=(sonarqube_admin_username, sonarqube_admin_password))
		res = json.loads(req.content)
		bugs = []
		major_bugs = []
		critical_bugs = []
		minor_bugs = []
		blocker_bugs = []

		for issue in range(len(res['issues'])):
			if res['issues'][issue]['status'] == "OPEN":
				if res['issues'][issue]['severity'] == "MAJOR":
					major_bug = {
						"message" : res['issues'][issue]['message'],
						"severity" : res['issues'][issue]['severity'],
						"component" : res['issues'][issue]['component']
						}
					major_bugs.append(major_bug)
				if res['issues'][issue]['severity'] == "CRITICAL":
					critical_bug = {
						"message" : res['issues'][issue]['message'],
						"severity" : res['issues'][issue]['severity'],
						"component" : res['issues'][issue]['component']
						}
					critical_bugs.append(critical_bug)
				if res['issues'][issue]['severity'] == "MINOR":
					minor_bug = {
						"message" : res['issues'][issue]['message'],
						"severity" : res['issues'][issue]['severity'],
						"component" : res['issues'][issue]['component']
						}
					minor_bugs.append(minor_bug)
				if res['issues'][issue]['severity'] == "BLOCKER":
					blocker_bug = {
						"message" : res['issues'][issue]['message'],
						"severity" : res['issues'][issue]['severity'],
						"component" : res['issues'][issue]['component']
						}	
					blocker_bugs.append(blocker_bug)
		return major_bugs, critical_bugs, minor_bugs, blocker_bugs
	except:
		raise Exception("Unable to find bug list")


def convertToPDF(project_name, current_date_time):
        pdf_name = project_name + "-" + current_date_time + ".pdf"
        root = os.path.dirname(os.path.abspath(__file__))
        filename = os.path.join(root, 'html', '{}.html'.format(project_name))
        try:
                pdfkit.from_file(filename, "pdf_reports/" + pdf_name)
                return True
        except Exception as e:
                print(e)
        return False



#OLD DATA
componentID = getComponentID(getProjectKey(sonarqube_analysis_project_name))

projectKey = getProjectKey(sonarqube_analysis_project_name)

bugsByRules, name = getBugsByRules(getLanguage(componentID),projectKey,ruleID)

bugCountByRules = getbugCountByRule(getLanguage(componentID),projectKey,ruleID)

technical_debt_in_days = getMetricResult("sqale_index", componentID)

number_of_bugs = getMetricResult("bugs", componentID)

number_of_vulnerabilities = getMetricResult("vulnerabilities", componentID )

code_smells = getMetricResult("code_smells", componentID)

duplicated_blocks = getMetricResult("duplicated_blocks", componentID )

duplicated_lines_density = getMetricResult("duplicated_lines_density", componentID )

nloc = getMetricResult("ncloc", componentID )

major = getIssueCount("MAJOR", projectKey )

minor = getIssueCount("MINOR", projectKey )

blockers = getIssueCount("BLOCKER", projectKey )

critical = getIssueCount("CRITICAL", projectKey )

lastAnalysisDate = getLastAnalysisDate( projectKey )

#NEW DATA
number_of_new_bugs = getLeakPeriodMetricResult("new_bugs", componentID )

number_of_new_vulnerabilities = getLeakPeriodMetricResult("new_vulnerabilities", componentID )

new_technical_debt_in_days = getLeakPeriodMetricResult("new_technical_debt", componentID )


old_data = { 	"Project Name"  :  sonarqube_analysis_project_name, 
			"Number of bugs" : number_of_bugs, 
			"Vulnerabilities" : number_of_vulnerabilities, 
			"Code smells" : code_smells, 
			"Technical debt in days" : technical_debt_in_days,
			"Duplicated blocks" : duplicated_blocks,
			"Duplications in percentage" : duplicated_lines_density,
            "Major issues" : major,
            "Minor issues" : minor,
            "Blockers" : blockers,
            "Critical" : critical
		}

new_data = { "Project Name"  :  sonarqube_analysis_project_name, 
			 "New bugs" : number_of_new_bugs,
			 "New Vulnerabilities" : number_of_new_vulnerabilities,
			 "New Debt" : new_technical_debt_in_days
			}


project_key = getProjectKey(sonarqube_analysis_project_name)
leak_period_date = getLeakPeriodDate(projectKey)
quality_gate_status = getMetricResult("alert_status", componentID )
major_bugs, critical_bugs, minor_bugs, blocker_bugs = getBugList(projectKey)

try:
	with open(filename, 'w') as f:
		f.write(template.render(
		h1 = sonarqube_analysis_project_name,
		title = sonarqube_analysis_project_name,
		status = quality_gate_status,
		data    = old_data,
		new_data = new_data,
		leak_period_date = leak_period_date,
		major_bugs = major_bugs,
		critical_bugs = critical_bugs,
		minor_bugs = minor_bugs,
		blocker_bugs = blocker_bugs,
		key = project_key,
		number_of_bugs = number_of_bugs, 
		number_of_vulnerabilities = number_of_vulnerabilities, 
		code_smells = code_smells,
		sev_major = major,
		sev_minor = minor,
		sev_blockers = blockers,
		sev_critical = critical,
		technical_debt = technical_debt_in_days,
		duplicated_blocks = duplicated_blocks,
		duplications_percentage = duplicated_lines_density,
		number_of_new_bugs = number_of_new_bugs,
		number_of_new_vulnerabilities = number_of_new_vulnerabilities,
		new_technical_debt_in_days = new_technical_debt_in_days,
		lastAnalysisDate = lastAnalysisDate,
		current_date = current_date,
		sonarqube_server_url = sonarqube_server_url,
		sonarqube_server_port = sonarqube_server_port,
		bugsByRules = bugsByRules,
		name = name,
		bugCountByRules = bugCountByRules,
		nloc = nloc
		))
	print("HTML Report Published")
	print("Creating PDF Report")
	if convertToPDF(sonarqube_analysis_project_name, current_date_time) == True:
		print("PDF Saved")
	else:
		print("Unable to save PDF")
except Exception as e:
	print(e)
