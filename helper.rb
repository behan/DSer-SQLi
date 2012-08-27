=begin
	JAVA Object Serialization Analyzer (Helper methods)
	Manish S. Saindane
	Contact: manish@andlabs.org
	(C)Attack & Defense Labs (http://www.andlabs.org)
=end

# Use this to create a temporary ByteArray buffer
def make_buffer(obj)
  bos = java.io.ByteArrayOutputStream.new
  oos = java.io.ObjectOutputStream.new(bos)
  oos.writeObject(obj)
  buff = bos.toByteArray
end

# Changes the content length according to the length of the new object
def modify_header(message, p_start, buff)
  header = String.from_java_bytes(message[0..p_start-1])
  mod_header = header.gsub(/Content-Length:\s*\d*/i, "Content-Length: #{buff.size}")
  return mod_header.to_java_bytes
end

# Gets all the declared fields within the object
def get_fields(obj)
  obj.java_class.declared_fields
end

# Gets all the constructors defined in the object
def get_constructors(obj)
  obj.java_class.declared_constructors
end

# Gets all the instance methods defined in the object
def get_instance_methods(obj)
  obj.java_class.declared_instance_methods
end

# Gets the value assigned to a particular field within an object
def get_field_value(obj, field)
  temp = obj.java_class.declared_field(field)
  temp.accessible = true unless temp.accessible?
  temp.value(obj.java_object)
end

# Sets the value of a particular field to a user defined value
def set_field_value(obj, field, value)
  temp = obj.java_class.declared_field(field)
  temp.accessible = true unless temp.accessible?
  temp.set_value(obj.java_object, value)
end

# Prints the details of the object
def print_class(obj)
  consts = get_constructors(obj)
  fields = get_fields(obj)
  methods = get_instance_methods(obj)
  puts "Constructors for #{obj.java_class.canonical_name}:"
  puts "================================================"
  consts.each {|c| puts c}
  puts
  puts "Fields for #{obj.java_class.canonical_name}:"
  puts "================================================"
  fields.each {|f| puts f}
  puts
  puts "Instance Methods for #{obj.java_class.canonical_name}:"
  puts "================================================"
  methods.each {|m| puts m}
end

class String
  def hexdump
    i = 1
    rr = ""
    while (self.length > 16*(i-1))
      a=self.slice(16*(i-1)..(16*i)-1)
      rr += sprintf("%06x: %4.4x %4.4x %4.4x %4.4x   %4.4x %4.4x %4.4x %4.4x ", (i-1)*16,  *a.unpack("n16"))
      rr += sprintf("|%s|\n", a.tr("^\040-\176","."))
      i += 1
    end
    return rr
  end
end