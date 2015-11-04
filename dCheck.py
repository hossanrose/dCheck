#!env/bin/python

from flask import Flask, session, redirect, url_for, escape, request, flash, render_template, abort
import subprocess, shlex, re, socket

app = Flask(__name__)
app.config.from_object('config')

class dCheck(object):
	RECORDS=['A','MX','TXT','NS']
	def __init__(self,domain):
		self.domain=domain

#command execution
	def exec_cmd(self,command):
		print (command)
		run = subprocess.Popen(command, stdout = subprocess.PIPE,stderr=subprocess.PIPE)
		stdout,stderr = run.communicate()
		#print(stdout, stderr)
		output=stdout.splitlines()
		return output
#Check if A record is present

	def dig_A(self):
		match_string='^' +self.domain+'.(\\t)*[0-9]*(\\t)*IN(\\t)*A'
		p =re.compile(match_string)
		print match_string, p
		command=['/usr/bin/dig','A',self.domain]
		output=self.exec_cmd(command)
		print output
		new_out=[]
		for outline in output:
                                if p.match(outline):
					new_out.append(outline)
		return new_out
			
#Dig function for different records
	def exec_dig(self):
		new_out=[]
		self.dic_rec={}
		for record in self.RECORDS:
			command=['/usr/bin/dig',record, self.domain]
			match_string='^' +self.domain+'.(\\t)*[0-9]*(\\t)*IN(\\t)*'+record
			p =re.compile(match_string)
			print match_string, p
			output=self.exec_cmd(command)
			new_out.append("--------------"+record+ " record--------------")
			for outline in output:
				if p.match(outline):
					new_out.append(outline)
					self.dic_rec[record]=outline
		print self.dic_rec
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
		if 'A' not in self.dic_rec:
			output = ["No website detected: A record missing"]
		else:
			output=self.exec_cmd(['/usr/bin/curl','-I','-m', '5',self.domain])
		#print output
		return output

# Check IP information
	def ip_check(self):
		if 'A' not in self.dic_rec:
                        new_out = ["Domain not resolving to an IP"]
                else:
			ip=socket.gethostbyname(self.domain) 
			output=self.exec_cmd(['/usr/bin/whois',ip])
			match_string='^(irt:|OrgName:|address:|Address:|City:|StateProv:|PostalCode:|country:|Country:)'
        		p =re.compile(match_string)
			print match_string, p
        		new_out=[]
        		for outline in output:
                		if p.match(outline):
                        		new_out.append(outline)
		return new_out
# Check ports
	def nmap_check(self):
		if 'A' not in self.dic_rec:
                        new_out = ["No A record found for port check"]
		else:
			output=self.exec_cmd(['/usr/bin/nmap', '-F', self.domain])
			#print output
			match_string='(nmap|Nmap)'
			p =re.compile(match_string)
                	print match_string, p
			new_out=[]
                	for outline in output:
                        	if not p.search(outline):
                                	new_out.append(outline)
                return new_out

#Main function call
	def main_check(self):
		output=[]
		output.append(self.exec_dig())
        	output.append(self.domain_check())
        	output.append(self.curl_check())
        	output.append(self.ip_check())
		output.append(self.nmap_check())
		return output
#iptools
@app.route('/<domain>')
@app.route('/', methods=['GET', 'POST'])
def index(domain=None):
	if request.method == 'POST':
		domain = request.form['domain']
		call=dCheck(domain)
		output=call.main_check()
		return render_template('index.html', dig=output[0],whois=output[1],headers=output[2],ipinfo=output[3],nmap=output[4])
	if (not domain == None):
		call=dCheck(domain)
		output=call.main_check()
		return render_template('index.html', dig=output[0],whois=output[1],headers=output[2],ipinfo=output[3],nmap=output[4])
	return render_template('index.html') 

if __name__ == "__main__":
	app.run(debug=True,host='0.0.0.0')
