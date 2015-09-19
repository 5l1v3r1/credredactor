#!/usr/bin/ruby

require 'terminal-table'
require 'date'
require 'time'
require 'optparse'

class Loader
	attr_accessor :infile, :lines
	def initialize(file_name)
		@infile = File.new(file_name,"r+")
		@lines = []
		@infile.each {|l| @lines << l.gsub(/\s/,'') unless l == ""}
		@infile.close()
		@lines.delete('')
	end
end

class CredProcessor

=begin

ATTRIBUTES

	:credentials
		initial credential records
		formatting is indicated by the :format attribute
		loaded using the Loader class

	:delimiter
		defines the delimiter segmenting the [username|domain] and password field
		defaults to ':'
			test.net\archangel:7ryh4rd3R
		works hand-in-hand with :format

	:domains
		array containing a domains
		derived from credentials

	:format
		indicates how credentials are formatted
		see the section defining delimiters below
		Credential Formats:
			a --> [user]@[domain][delimiter][password]
				archangel@test.net:7ryh4rd3R
			b --> [domain]\[user][delimiter]][password]
				test.net\archangel:7ryh4rd3R
			c --> [username][delimiter][password]
				archangel:7ryh4rd3R

	:processed ( credentials[domain][username] = [password,redacted_password] )
		a dictionary containing dictionaries
		keys = domains
			each domain is a dictionary containing 
			keys are usernames associated with credentials 
			value is an array containing a password and redacted password
				[username => [password,redacted]]

	:usernames
		array containing usernames
		derived from credentials

	:passwords
		array containg raw passwords
		derived from credentials

	:client
		name of the client associated with cracked passwords
		will appear in dumpCreds() summary table


=end

attr_accessor :credentials, :processed, :domains, :usernames, :passwords
attr_reader :client, :delimiter, :format

	def initialize(credentials,format=:a,delimiter=":",client=:DEFAULT,csv=nil)
		
		@credentials = credentials.sort!()
		@format = format
		@delimiter = delimiter
		@domains = getDomains()		
		@processed = loadProcessed()
		@usernames, @passwords = loadRaw()
		@client = client

	end

	def loadProcessed()
		processed = {}
		@domains.each {|dom| processed[dom] = {}}
		credentials.each {|cred|
			case format

			when :a
				cred =~ /(^.*?@)(.*?#{@delimiter})(.+$)/

				username, domain, password = $1, $2, $3

				username.gsub!('@','').downcase!()
				domain.gsub!(@delimiter,'')
	
				processed[domain][username] = [password,redact(password)]

			when :b	
				cred =~ /(^.*?\\)(.*?#{@delimiter})(.+$)/

				domain, username, password = $1, $2, $3

				username.gsub!(@delimiter,'').downcase!()
				domain.gsub!('\\','')

				processed[domain][username] = [password,redact(password)]

			when :c
				split = cred.split(':')
				username,password = split[0], split[1]
				processed[:DEFAULT][username] = [password,redact(password)]

			end

		}
		return processed
	end

	def loadRaw()
		passwords = []
		usernames = []
		@processed.each do |domains,accounts|
			accounts.each do |username,credentials|
				passwords << credentials[0]
				usernames << username
			end
		end
		return usernames,passwords
	end

	def getDomains()
		domains = []
		@credentials.each {|cred|
			case @format
			when :a 
				cred =~ /(^.*?@)(.*?#{@delimiter})(.+$)/
				domains << $2.gsub(@delimiter,'')
			when :b
				cred =~ /(^.*?\\)(.*?#{@delimiter})(.+$)/
				domains << $1.gsub('\\','')
			when :c
				domains << :DEFAULT
			end
		}
		return domains.uniq()
	end

	def redact(pass)
		redacted = ""
		p_len = pass.length()
		floor = (p_len / 3)
		ceiling = (p_len - 2)
		until (redacted.count('*') >= floor and redacted.count('*') < ceiling) do
			redacted = ""
			pass.split("").each { |l|
				rando = rand(0..2)
				if rando == 0
					redacted += l
				else
					redacted += '*'
				end
			}
		end
		return redacted
	end

	def analyzePassword(password)
		analysis = []
		password.split('').each do |l|
			case l
			when /[a-z]/
				analysis << "c"
			when /[A-Z]/
				analysis << "C"
			when /[0-9]/
				analysis << "d"
			else
				analysis << "s"
			end
		end
		return analysis.join()
	end

	def dumpCredentials()
		records = []
		@processed.each do |domain,accounts| 

			accounts.each do |account,passwords|
				redacted = passwords[1]
				password = passwords[0]
				complexity = analyzePassword(password)
				case @format
				when :a,:b
					records << [domain,account,redacted,password.length().to_s,complexity]
				when :c
					records << [account,redacted,password.length(),complexity]
				end
			end

		end

		title = "Compromised Accounts\nClient: #{@client}, Date/Time: #{Date::today.to_s} / #{Time::now.to_s.split[1]}"

		case @format
		when :a,:b
			table = Terminal::Table.new :title => title,
										:headings=>["Domain","Username","Redacted","Length","Complexity"],
										:rows => records
		when :c
			table = Terminal::Table.new :title => title,
										:headings=>["Username","Redacted","Length","Complexity"],
										:rows => records
		end

		puts table
	end	

end

class Interface

	def self.parse(args)
		options = {}

		formats = {:a=>["[user]@[domain][delimiter][password]","archangel@test.net:7ryh4rd3R"],
		   :b=>["[domain][user]\\[delimiter]][password]","test.net\\archangel:7ryh4rd3R"],
		   :c=>["[username][delimiter][password]","archangel:7ryh4rd3R"]}

		formed_formats = String.new()
		
		formats.each do |format,ary| 
			formed_formats = formed_formats + "\t\t\t\t#{format}: #{ary[0]}, e.g. #{ary[1]}\n"
		end

		format_guidance = "The following password file formats are supported:\n\n#{formed_formats}\t"

		opt_parser = OptionParser::new do |opts|
			opts.banner = "Usage: #{$0} [options]"
			opts.separator "Specific Options:"
			
			opts.on("-p","--passfile PASSWORD_FILE", "Password file to be parsed") do |p|
				options[:passfile] = p
			end

			opts.on("-f","--format [a|b|c]", format_guidance) do |f|
				f.downcase!
				case f
				when "a"
					f = :a
				when "b"
					f = :b
				when "c"
					f = :c
				end
				options[:format] = f
			end

			opts.on("-d","--delimiter [character]", "Delimiter character") do |d|
				options[:delimiter] = d
			end

			opts.on("-c","--client [client name]", "Name of client") do |c|
				options[:client] = c
			end

		end

	opt_parser.parse!(args)
	options

	end
end

ARGV << "-h" if ARGV == []
options = Interface.parse(ARGV)
loader = Loader.new(options[:passfile])
creds = CredProcessor.new(loader.lines,options[:format],options[:delimiter],options[:client])
creds.dumpCredentials()
