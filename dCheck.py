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

#Dig for A record
	def exec_dig_A(self):
		command=['/usr/bin/dig','A',self.domain]
		match_string='^' +self.domain+'.(\\t)*[0-9]*(\\t)*IN(\\t)*A'
		p =re.compile(match_string)
		output=self.exec_cmd(command)
		new_out=[]
		for outline in output:
			if p.match(outline):
				the_rec=re.split(r'\t+',outline)
				new_out.append(the_rec[-1])
		return new_out	

#Dig function for different records
	def exec_dig(self):
		new_out=[]
		dic_dig={}
		for record in self.RECORDS:
			command=['/usr/bin/dig',record, self.domain]
			match_string='^' +self.domain+'.(\\t)*[0-9]*(\\t)*IN(\\t)*'+record
			p =re.compile(match_string)
			print match_string, p
			output=self.exec_cmd(command)
			new_out.append("--------------"+record+ " record--------------")
			#Intialize a list for each record, so that mulitple results for same record can be saved
			for outline in output:
				if p.match(outline):
					new_out.append(outline)
					#Uses regular expression to split the string based on tab
					the_rec=re.split(r'\t+',outline)
					value=''.join(the_rec[-1])
					dic_dig.setdefault(record,[]).append(value)
		print dic_dig
		return (new_out,dic_dig)

#Check the domains whois enteries
	def domain_check(self):
		output=self.exec_cmd(['/usr/bin/whois',self.domain])
		#print output
		match_string='^\s*(Regist|Name Server:|Updat|Creat|Expir|Last|Admin)'
		p =re.compile(match_string)
		print match_string, p
		new_out=[]
		dic_whois={}
		for outline in output:
			if p.match(outline):
				new_out.append(outline)
				the_rec=outline.split(':')
				value=''.join(the_rec[1:])
				# setdefault menthod will append if the key already
				dic_whois.setdefault(the_rec[0],[]).append(value)
		#print dic_whois
		return (sorted(new_out),dic_whois)

# Check the domains headers
	def curl_check(self):
		dic_curl={}
		if self.dig_A ==[]:
			output = ["No website detected: A record missing"]
		else:
			output=self.exec_cmd(['/usr/bin/curl','-I','-m', '5',self.domain])
			for outline in output:
				the_rec=outline.split(':')
				value=''.join(the_rec[1:])	
				dic_curl.setdefault(the_rec[0],[]).append(value)
		print dic_curl
		return (output,dic_curl)

# Check IP information
	def ip_check(self):
		dic_ip={}
		if self.dig_A ==[]:
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
					the_rec=outline.split(':')
					value=''.join(the_rec[1:])
					dic_ip.setdefault(the_rec[0],[]).append(value)
		print dic_ip
		return (new_out,dic_ip)

# Check ports
	def nmap_check(self):
		dic_nmap={}
		if self.dig_A ==[]:
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
                return (new_out,dic_nmap)

#Main function call
	def main_check(self):
		output=[]
		self.dig_A=self.exec_dig_A()
		print self.dig_A
		output.append(self.exec_dig()[0])
        	output.append(self.domain_check()[0])
        	output.append(self.curl_check()[0])
        	output.append(self.ip_check()[0])
		output.append(self.nmap_check()[0])
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
