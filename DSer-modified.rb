=begin
	JAVA Object Serialization Analyzer
	Manish S. Saindane
	Contact: manish@andlabs.org
	(C)Attack & Defense Labs (http://www.andlabs.org)
	
	Modified by Dylan Webb (dylan.webb@alliedinfosecurity.com) to integrate SQLi tools that take proxies
=end

include Java
require 'rubygems'
require 'irb'
require 'irb/completion'
require 'buby'
require 'helper.rb'

import javax.swing.JFrame
import java.awt.event.ActionListener
import java.util.HashMap

Dir[File.dirname(__FILE__) + '/lib/*.jar'].each {|file| require file }

$intercept = true; $status = "ON"

=begin
	This module will basically setup an IRB session. It has been picked up from the 
	ruby debugger code.
=end

module IRB
	def self.start_session(binding)
		unless $irb
		IRB.setup(nil)
		IRB.conf[:PROMPT][:DSER] = {:PROMPT_N => "[DSer]>> ",
									:PROMPT_I => "[DSer]>> ",
									:PROMPT_S => "[DSer]>> %l",
									:PROMPT_C => "[DSer]>>* ",
									:RETURN => "=> %s\n"
									}
		IRB.conf[:PROMPT_MODE] = :DSER
		end
		
		workspace = WorkSpace.new(binding)

		if @CONF[:SCRIPT]
		$irb = Irb.new(workspace, @CONF[:SCRIPT])
		else
		$irb = Irb.new(workspace)
		end

		@CONF[:IRB_RC].call($irb.context) if @CONF[:IRB_RC]
		@CONF[:MAIN_CONTEXT] = $irb.context
		
		trap("SIGINT") do
		$irb.signal_handle
		end

		catch(:IRB_EXIT) do
		$irb.eval_input
		end
	end
end


=begin
	The Module DSer is basically where all the magic happens. As of now the evt_proxy_message_raw method
	will be used to analyze the request/responses trapped by Burp. This method is setup to be triggered
	when it observers any request/response containing a JAVA serialzed object.
	
	Currently this module exposes a JRuby shell to the pentester and exposes an Object obj to work with.
	
=end

module DSer

	def evt_proxy_message_raw(*param)
		msg_ref, is_req, rhost, rport, is_https, http_meth, url,
		resourceType, status, req_content_type, message, action = param
	
		if (is_req && http_meth == "POST") ||
		(is_req == false && (req_content_type == "application/octet-stream" || req_content_type == "application/x-java-serialized-object"))
			
			puts "+++++++++++++++++++++++++++++++++++++++++++++++++++++"
			puts "DSer writtin by Manish Saindane"
			puts "Adaptation by Dylan Webb to allow tools such as sqlmap to work their magic" 
			puts "+++++++++++++++++++++++++++++++++++++++++++++++++++++"
			puts
			
			#Import a template file and de-serialize
			template = File.open("C:/template.raw", "rb")
			s = template.read
	
			b = s.to_java_bytes
			
			p_start = b.find_index(-84) if b.find_index(-19) == (b.find_index(-84) + 1)
			
			bis = java.io.ByteArrayInputStream.new(b)
			ois = java.io.ObjectInputStream.new(bis)
			obj = ois.read_object
			
			#We get our SQLi from another tool
			newparameters = getParameters(message).to_a.select {|x| x[2] == "body parameter"}.map {|p| [p[0], p[1].chomp]}
			injectedvalue=newparameters[0][1]
			
			#Create a temporary hashmap
			temp_obj = HashMap.new
			temp_obj = obj.getContent
			#What are you trying to inject?
			temp_obj.put "CHANGEME", injectedvalue  
			set_field_value(obj, "obj", temp_obj)
			
			puts "Injecting " + injectedvalue				
	
			#action[0] = Buby::ACTION_DONT_INTERCEPT
			#if $intercept #&& is_req
			#	IRB.start_session(binding)
			#end
	
			#Re-serialize data and adjust HTTP header length
			buff = make_buffer(obj)
			header = String.from_java_bytes(message[0..p_start-(injectedvalue.size)-5]) 
			mod_header = header.gsub(/Content-Length:\s*\d*/i, "Content-Length: #{buff.size}")
			new_header = mod_header.to_java_bytes
			new_msg = new_header + buff
			
			#Send it back out :)
			return new_msg
		end		
	end
end

if __FILE__ == $0
	# Initializing Burp
	$burp = Buby.new()
	$burp.extend(DSer)
	$burp.start_burp()
	
	frame = javax.swing.JFrame.new "Intercept"
	frame.set_default_close_operation javax.swing.JFrame::EXIT_ON_CLOSE
	frame.set_size 130, 100

	button = javax.swing.JToggleButton.new "Intercept #$status", true
	frame.content_pane.add button

	frame.visible = true

	class BtnClicked
		include ActionListener

		def actionPerformed(act)
		if $intercept == true then
			$intercept = false
			$status = "OFF"
		else
			$intercept = true
			$status = "ON"
		end
		act.source.text = "Intercept #$status"
		end
		
	end

	button.add_action_listener BtnClicked.new
end
