from rest_framework.throttling import UserRateThrottle, AnonRateThrottle, SimpleRateThrottle, BaseThrottle
from django.core.cache import cache
import time
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import InvalidToken
from UserAuth.models import UserProfile

class IPThrottleManager:

    @staticmethod
    def get_request_ip(requests):
        x_forward_for = requests.META.get("HTTP_X_FORWARD_FOR")
        if x_forward_for:
            ip = x_forward_for.split(',')[0].strip()
        
        else:
            ip = requests.META.get("REMOTE_ADDR")
        
        return ip or '0.0.0.0'

class UserIdManager:

    @staticmethod
    def get_user_id(request):
        user = request.user

        return user.id

class OTPResendThrottle(BaseThrottle):
    MAX_LIMIT = 3
    INTERVAL = 60

    def can_resend_otp(self, request):
        email = request.data.get("email")
        ip = IPThrottleManager.get_request_ip(request)

        if not email:
            return True

        throttle_key = f"otp_resend:{email}:{ip}"

        try:
            current_count = cache.incr(throttle_key)
        except ValueError:
            cache.set(throttle_key, 1, timeout=self.INTERVAL)
            return True

        if current_count == 1:
            cache.expire(throttle_key, self.INTERVAL)

        if current_count > self.MAX_LIMIT:
            return False


        return True
    

    def allow_request(self, request, view):
        return self.can_resend_otp(request)
    

    def throttle_failure(self, requests):
        pass



class OTPVerificationThrottle(UserRateThrottle): ## I gave up I was not able to find the bug and my mouse broke Fuck this shit !! update
    scope = "verify_otp" ## If sombady can write better custom throttel help would be appritiated
# Wanted to use burst throtteling technique as the user is alredy logged in toomuch throttle is not that necessary yet it is kind of important Thanks!!

'''
Attack Pattern
1. Same IP + many emails
2. Different IPs + same pattern emails
3. Disposable email domains

Multi-Layer Identity
1. IP → stops burst from one machine
2. Email → stops repeated attempts on same email
3. IP + Email → stops targeted abuse

Recomended Keys
1. signup_ip:{ip}
2. signup_email:{email}
3. signup_combo:{ip}:{email}
'''
class SignupThrottle(BaseThrottle):
    #scope = "signup"
    MAX_IP_ABUSE = 5
    MAX_EMAIL_ABUSE = 3
    MAX_COMBO_ABUSE = 2
    INTERVAL = 3600

    def can_signup(self, request):
        email = request.data.get("email").lower().strip()
        ip = IPThrottleManager.get_request_ip(request)

        if not email or not ip:
            return True
        
        mapp = {
            'ip': {
                'key': f"signup_ip:{ip}",
                'limit': self.MAX_IP_ABUSE
            },
            'email': {
                'key': f"signup_email:{email}",
                'limit': self.MAX_EMAIL_ABUSE
            },
            'combo': {
                'key': f"signup_combo:{ip}:{email}",
                'limit': self.MAX_COMBO_ABUSE
            }
        }

        now = time.time()
        valid_historys = {}

        for label, data in mapp.items():  ## yoyo The labels has to do its job after this bit gets sorted out
            cache_key = data['key']
            limit = data['limit']

            history = cache.get(key=cache_key) or []

            while history and history[-1] <= now - self.INTERVAL:
                history.pop()


            if len(history) >= limit:
                return False
            
            valid_historys[cache_key] = history

        for cache_key, history in valid_historys.items():
            history.insert(0, now)
            cache.set(cache_key, history, self.INTERVAL)

        return True
    

    def allow_request(self, request, view):
        return self.can_signup(request)
    

    def throttle_failure(self):
        pass



'''
Attack Pattern
1. Same email, many passwords  by email i mean identifier as username_email is allowed
2. Same IP, many accounts
3. Distributed attack (botnet)

Key:
1. identifier: Brute force guessing the password
2. ip: spam signup from same account
3. email+ip: added security
'''
class LoginThrottle(BaseThrottle):
    #scope = "login"

    MAX_IP_ABUSE = 5
    MAX_IDENTIFIER_ABUSE = 5
    MAX_COMBO_ABUSE = 2
    INTERVAL = 300

    def can_login(self, request):
        identifier = request.data.get("username_email")
        ip = IPThrottleManager.get_request_ip(request)
        print (ip)
        password = request.data.get("password")
        
        if not password:
            return True  # serializer would test this bit
        
        if not identifier:
            return False  # Will be used in the bit
        
        mapp = {
            'ip': {
                'key': f"login_ip:{ip}",
                'limit': self.MAX_IP_ABUSE
            },
            'identifier': {
                'key': f"login_identifier:{identifier}",
                'limit': self.MAX_IDENTIFIER_ABUSE
            },
            'combo': {
                'key': f"login_combo:{ip}_{identifier}",
                'limit': self.MAX_COMBO_ABUSE
            }
        }

        now = time.time()
        valid_history = {}

        for labels, data in mapp.items():
            cache_key = data["key"]
            limit = data["limit"]

            history = cache.get(key=cache_key) or []

            while history and history[-1] <= now - self.INTERVAL:
                history.pop()

            if len(history) >= limit:
                return False
            
            valid_history[cache_key] = history

        for cache_key, history in valid_history.items():
            history.insert(0, now)
            cache.set(cache_key, history, self.INTERVAL)

        return True
    

    def allow_request(self, request, view):
        return self.can_login(request)



'''
Attack Pattern
1. stolen token abuse
'''
class AccessTokenThrottle(BaseThrottle):
    #scope = "access_token"
    MAX_TOKEN_ABBUSE = 5
    MAX_IP_ABUSE = 20
    INTERVAL = 300

    def can_recive(self, request):
        raw_reftesh_token = request.data.get("refresh_token")
        ip = IPThrottleManager.get_request_ip(request)

        if not raw_reftesh_token:
            return False
        
        try:
            refresh_token = RefreshToken(raw_reftesh_token)
            jti = refresh_token["jti"]
        except InvalidToken:
            return False

        
        token_key = f"refresh_token:{jti}"
        ip_key = f"refresh_ip:{ip}"

        token_count = cache.get(token_key, 0)
        ip_count = cache.get(ip, 0)

        if token_count >= self.MAX_TOKEN_ABBUSE:
            return False
        
        if ip_count >= self.MAX_IP_ABUSE:
            return False
        
        cache.set(token_key, token_count + 1, timeout=self.INTERVAL)
        cache.set(ip_key, ip_count + 1, timeout=self.INTERVAL)

        return True
    
    def issue_new_access(Self, request):
        raw_refresh = request.data.get("refresh_token")

        try:
            refresh = RefreshToken(raw_refresh)
            access = str(refresh.access_token)
            return {"access": access}
        except InvalidToken:
            return None
    
    def allow_request(self, request, view):
        return self.can_recive(request)
        


'''
Attack Pattern
1. spam DB writes
'''
class CoreDataUpdateThrottle(BaseThrottle):
    #scope = "core_update"
    LIMIT = 2
    INTERVEL = 60

    def allow_update(self, request):

        key = f"heavy_update:{UserIdManager.get_user_id(request)}"
        history = cache.get(key, [])

        now = time.time()
        valid_history = []

        for times in history:
            if times > now - self.INTERVEL:
                valid_history.append(times)

        if len(valid_history) >= self.LIMIT:
            return False
        

        valid_history.append(now)
        cache.set(key, valid_history, timeout=self.INTERVEL)
        
        return True
    
    def allow_request(self, request, view):
        return self.allow_update(request)

'''
Attack Pattern
1. email spam
2. verification abuse

Heavy operation and imp data involved
'''
class UpdateEmailThrottle(BaseThrottle):
    #scope = "change_email"
    MAX_USER = 3
    MAX_EMAIL = 2
    MAX_COMBO = 1
    INTERVAL = 3600  # 1 hour

    def allow_update(self, request):
        user_id = UserIdManager.get_user_id(request)
        new_email = request.data.get("email").lower().strip()

        if not new_email:
            return False

        now = time.time()

        mapp = {
            "user": {"key": f"change_email_user:{user_id}", "limit": self.MAX_USER},
            "email": {"key": f"change_email_email:{new_email}", "limit": self.MAX_EMAIL},
            "combo": {"key": f"change_email_combo:{user_id}:{new_email}", "limit": self.MAX_COMBO}
        }

        valid_histories = {}
        throttled = False

        for label, data in mapp.items():
            cache_key = data["key"]
            limit = data["limit"]

            history = cache.get(cache_key, [])

            history = [t for t in history if t > now - self.INTERVAL]

            if len(history) >= limit:
                throttled = True
            valid_histories[cache_key] = history

        if throttled:
            return False

        for cache_key, history in valid_histories.items():
            history.append(now)
            cache.set(cache_key, history, timeout=self.INTERVAL)

        return True
    

    def allow_request(self, request, view):
        return UpdateEmailThrottle(request)


'''
Attack Pattern
1. brute-force old password
'''
class PasswordChangeThrottle(BaseThrottle):
    #scope = "user_password_update"
    MAX_USER = 3
    MAX_COMBO = 5
    INTERVAL = 3600

    def allow_update(self, request):
        user_id = request.user.id
        ip = request.META.get("REMOTE_ADDR")

        now = time.time()
        mapp = {
            "user": {"key": f"password_change_user:{user_id}", "limit": self.MAX_USER},
            "combo": {"key": f"password_change_combo:{user_id}:{ip}", "limit": self.MAX_COMBO}
        }

        valid_histories = {}
        
        throttled = False
        
        for label, data in mapp.items():
            cache_key = data["key"]
            limit = data["limit"]

            history = cache.get(cache_key, [])
            
            history = [t for t in history if t > now - self.INTERVAL]

            if len(history) >= limit:
                throttled = True
            valid_histories[cache_key] = history

        if throttled:
            return False

        for cache_key, history in valid_histories.items():
            history.append(now)
            cache.set(cache_key, history, timeout=self.INTERVAL)

        return True
    

    def allow_request(self, request, view):
        return self.allow_update(request)


'''
Attack Pattern
1. spam reset emails
2. DoS via email flooding
'''
class AnonPasswordChangeThrottle(BaseThrottle):
    #scope = "anon_password_update"
    MAX_EMAIL = 1
    MAX_COMBO = 1
    INTERVAL = 3600

    def allow_update(self, request):
        identifier = request.data.get("username_email", "").lower().strip()
        ip = request.META.get("REMOTE_ADDR")
        now = time.time()

        if not identifier:
            return True

        mapp = {
            "identifier": {"key": f"anon_pass_email:{identifier}", "limit": self.MAX_EMAIL},
            "combo": {"key": f"anon_pass_combo:{identifier}:{ip}", "limit": self.MAX_COMBO}
        }

        valid_histories = {}
        throttled = False

        for label, data in mapp.items():
            cache_key = data["key"]
            limit = data["limit"]

            history = cache.get(cache_key, [])
            new_history = []
            for timestamp in history:
                if timestamp > now - self.INTERVAL:
                    new_history.append(timestamp)

            if len(new_history) >= limit:
                throttled = True

            valid_histories[cache_key] = new_history
        if throttled:
            return False

        for cache_key, history in valid_histories.items():
            history.append(now)
            cache.set(cache_key, history, timeout=self.INTERVAL)

        return True
    

    def allow_request(self, request, view):
        return self.allow_update(request)
    

'''
 are getting throtteling errores'''