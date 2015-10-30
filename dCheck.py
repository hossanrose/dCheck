#!env/bin/python

from flask import Flask, session, redirect, url_for, escape, request, flash, render_template, abort
import subprocess, shlex, re, socket

app = Flask(__name__)
app.config.from_object('config')

class dCheck(object):
	def __init__(self,domain,records):
		self.domain=domain
		self.records=records

#command execution
	def exec_cmd(self,command):
		print (command)
		run = subprocess.Popen(command, stdout = subprocess.PIPE,stderr=subprocess.PIPE)
		stdout,stderr = run.communicate()
		#print(stdout, stderr)
		output=stdout.splitlines()
		return output

	def exec_dig(self):
		match_string='^' + self.domain+'\s*'+'[0-9]*'+'\s*'
		p =re.compile(match_string)
		print match_string, p
		new_out=[]
		for record in self.records:
			command=['/usr/bin/dig',record, self.domain]
			output=self.exec_cmd(command)
			new_out.append("--------------"+record+ " record--------------")
			for outline in output:
				if p.match(outline):
					new_out.append(outline)
		return new_out

#Check the domains whois enteries
	def domain_check(self):
		output=self.exec_cmd(['/usr/bin/whois',self.domain])
		#print output
		match_string='^\s*(Regist|Name Server:|Updat|Creat|Expir|Last|Admin)'
		p =re.compile(match_string)
		print match_string, p
		new_out=[]
		for outline in output:
			if p.match(outline):
				new_out.append(outline)
		return sorted(new_out)

# Check the domains headers
	def curl_check(self):
		output=self.exec_cmd(['/usr/bin/curl','-I',self.domain])
		#print output
		return output

# Check IP information
	def ip_check(self):
		ip=socket.gethostbyname(self.domain) 
		output=self.exec_cmd(['/usr/bin/whois',ip])
		match_string='^(OrgName:|Address:|City:|StateProv:|PostalCode:|Country:)'
        	p =re.compile(match_string)
		print match_string, p
        	new_out=[]
        	for outline in output:
                	if p.match(outline):
                        	new_out.append(outline)
		return new_out
#Main function call
	def main_check(self):
		output=[]
		output.append(self.exec_dig())
        	output.append(self.domain_check())
        	output.append(self.curl_check())
        	output.append(self.ip_check())
		return output
#iptools
@app.route('/<domain>')
@app.route('/', methods=['GET', 'POST'])
def index(domain=None):
    records=['A','MX','TXT','NS']
    if request.method == 'POST':
        domain = request.form['domain']
	call=dCheck(domain,records)
	output=call.main_check()
        return render_template('index.html', dig=output[0],whois=output[1],headers=output[2],ipinfo=output[3])
    if (not domain == None):
        call=dCheck(domain,records)
        output=call.main_check()
        return render_template('index.html', dig=output[0],whois=output[1],headers=output[2],ipinfo=output[3])
    return render_template('index.html') 

if __name__ == "__main__":
	app.run(debug=True,host='0.0.0.0')
