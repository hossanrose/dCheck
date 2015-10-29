#!env/bin/python

from flask import Flask, session, redirect, url_for, escape, request, flash, render_template, abort
import subprocess, shlex, re

app = Flask(__name__)
app.config.from_object('config')

#command execution
def exec_cmd(command):
	print (command)
	run = subprocess.Popen(command, stdout = subprocess.PIPE,stderr=subprocess.PIPE)
	stdout,stderr = run.communicate()
	#print(stdout, stderr)
	output=stdout.splitlines()
	return output
def exec_dig(domain,records):
	match_string='^' + domain+'\s*'+'[0-9]*'+'\s*'
	p =re.compile(match_string)
	print match_string, p
	new_out=[]
	for record in records:
		command=['/usr/bin/dig',record, domain]
		output=exec_cmd(command)
		new_out.append("--------------"+record+ " record--------------")
		for outline in output:
			if p.match(outline):
				new_out.append(outline)
	return new_out
#Check the domains whois enteries
def domain_check(domain):
	output=exec_cmd(['/usr/bin/whois',domain])
	#print output
	return output

# Check the domains headers
def curl_check(domain):
	output=exec_cmd(['/usr/bin/curl','-I',domain])
	#print output
	return output
     
#iptools
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        domain = request.form['domain']
        records=['A','MX','TXT','NS']
        dig=exec_dig(domain,records)
        whois=domain_check(domain)
        #print whois
        headers=curl_check(domain)
        return render_template('index.html', dig=dig,whois=whois,headers=headers)
    return render_template('index.html' ) 

if __name__ == "__main__":
	app.run(DEBUG=True,host='0.0.0.0')
