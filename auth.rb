require 'net/http'
require 'uri'
require 'digest/sha1'
require 'openssl'

class Authenticator
  RSA_MOD = 104890018807986556874007710914205443157030159668034197186125678960287470894290830530618284943118405110896322835449099433232093151168250152146023319326491587651685252774820340995950744075665455681760652136576493028733914892166700899109836291180881063097461175643998356321993663868233366705340758102567742483097
  RSA_KEY = 257
  
  attr_reader :serial
  
  def initialize(auth = nil)
    if auth
      @secret = auth[:secret]
      @serial = auth[:serial]
      @restore = auth[:restore]
    else
      new_auth
    end
  end
  
  def export
    {:secret => @secret, :serial => @serial, :restore => @restore}
  end

  def sha1time
    Digest::SHA1.hexdigest(Time.now.to_i.to_s)
  end

  def encrypt(data)
    n = data.unpack('H*')[0].to_i(16) ** RSA_KEY % RSA_MOD
    ret = ""
    while n > 0 do
      n, m = n.divmod(256)
    	ret = m.chr + ret
    end
    ret
  end

  def new_auth
    http = Net::HTTP.new('m.us.mobileservice.blizzard.com')
    enc = (sha1time+sha1time)[0,37]
    unencrypted_data = (1.chr)+enc+"US"+"Motorola RAZR v3"
    encrypted_data = encrypt(unencrypted_data)

    resp, data = http.post("/enrollment/enroll.htm", encrypted_data, {"Content-Type" => "application/octet-stream"})
    encrypted = resp.body[8, 37]

    z = encrypted.unpack("C*")
    y = enc.unpack("C*")
    z.length.times { |w| z[w] ^= y[w] }
    z = z.pack("C*")

    @secret = z[0,20].unpack("H*")[0]
    @serial = z[20,17]
  end
  
  def process_restore
    restore_code = @restore.upcase.unpack("C*")
    restore_code.length.times do |w|
      c = restore_code[w]
      if(c > 47 && c < 58) then
        c -= 48 
      else    
        mod = c - 55
        mod -= 1 if c > 72
        mod -= 1 if c > 75
        mod -= 1 if c > 78
        mod -= 1 if c > 82
        c = mod
      end
      restore_code[w] = c
    end
    restore_code.pack("C*")
  end
  
  def restore
    http = Net::HTTP.new('m.us.mobileservice.blizzard.com')
    serial = @serial.gsub("-", "")
    challenge = http.post("/enrollment/initiatePaperRestore.htm", serial, {"Content-Type" => "application/octet-stream"}).body
    restore_code = process_restore
    
    hmac = OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new('sha1'), restore_code, serial+challenge)
    enc_key = (sha1time+sha1time)[0,20]
    data = serial+encrypt(hmac+enc_key)
    
    response = http.post("/enrollment/validatePaperRestore.htm", data, {"Content-Type" => "application/octet-stream"}).body
    data = response.unpack("C*")
    otp = enc_key.unpack("C*")
    data.length.times { |w| data[w] ^= otp[w] }
    data = data.pack("C*")
    @secret = data[0,20].unpack("H*")[0]
  end

  def generate_code(interval = [Time.now.to_i / 30])
    interval = interval.pack("Q*").reverse
    hmac = OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new('sha1'), [@secret].pack("H*"), interval)
    start = hmac[19].ord & 0x0f
    pre_code = hmac[start, 4].reverse.unpack("L*")[0] & 0x7fffffff
    code = pre_code % 100000000
    code.to_s.rjust(8, "0")
  end
end
