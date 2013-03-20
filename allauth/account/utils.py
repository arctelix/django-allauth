import hashlib
import random

from datetime import timedelta
try:
    from django.utils.timezone import now
except ImportError:
    from datetime import datetime
    now = datetime.now

from django.contrib import messages
from django.shortcuts import render
from django.contrib.sites.models import Site
from django.conf import settings
from django.core.urlresolvers import reverse
from django.contrib.auth import login
from django.utils.translation import ugettext_lazy as _, ugettext
from django.http import HttpResponseRedirect

from allauth.utils import import_callable

import signals

from app_settings import EmailVerificationMethod
import app_settings
from adapter import get_adapter

LOGIN_REDIRECT_URLNAME = getattr(settings, "LOGIN_REDIRECT_URLNAME", "")


def get_default_redirect(request, redirect_field_name="next",
        login_redirect_urlname=LOGIN_REDIRECT_URLNAME, session_key_value="redirect_to"):
    """
    Returns the URL to be used in login procedures by looking at different
    values in the following order:

    - a REQUEST value, GET or POST, named "next" by default.
    - LOGIN_REDIRECT_URL - the URL in the setting
    - LOGIN_REDIRECT_URLNAME - the name of a URLconf entry in the settings
    """
    if login_redirect_urlname:
        default_redirect_to = reverse(login_redirect_urlname)
    else:
        default_redirect_to = get_adapter().get_login_redirect_url(request)
    redirect_to = request.REQUEST.get(redirect_field_name)
    if not redirect_to:
        # try the session if available
        if hasattr(request, "session"):
            redirect_to = request.session.get(session_key_value)
    # light security check -- make sure redirect_to isn't garabage.
    if not redirect_to or "://" in redirect_to or " " in redirect_to:
        redirect_to = default_redirect_to
    return redirect_to



_user_display_callable = None

def user_display(user):
    global _user_display_callable
    if not _user_display_callable:
        f = getattr(settings, "ACCOUNT_USER_DISPLAY",
                    lambda user: user.username)
        _user_display_callable = import_callable(f)
    return _user_display_callable(user)


# def has_openid(request):
#     """
#     Given a HttpRequest determine whether the OpenID on it is associated thus
#     allowing caller to know whether OpenID is good to depend on.
#     """
#     from django_openid.models import UserOpenidAssociation
#     for association in UserOpenidAssociation.objects.filter(user=request.user):
#         if association.openid == unicode(request.openid):
#             return True
#     return False


def perform_login(request, user, redirect_url=None):
    from models import EmailAddress

    # not is_active: social users are redirected to a template
    # local users are stopped due to form validation checking is_active
    assert user.is_active
    if (app_settings.EMAIL_VERIFICATION == EmailVerificationMethod.MANDATORY
        and not EmailAddress.objects.filter(user=user,
                                            verified=True).exists()):
        send_email_confirmation(request, user)
        return render(request,
                      "account/verification_sent.html",
                      { "email": user.email })
    # HACK: This may not be nice. The proper Django way is to use an
    # authentication backend, but I fail to see any added benefit
    # whereas I do see the downsides (having to bother the integrator
    # to set up authentication backends in settings.py
    if not hasattr(user, 'backend'):
        user.backend = "django.contrib.auth.backends.ModelBackend"
    signals.user_logged_in.send(sender=user.__class__, 
                                request=request, 
                                user=user)
    login(request, user)
    messages.add_message(request, messages.SUCCESS,
                         ugettext("Successfully signed in as %(user)s.") % { "user": user_display(user) } )

    if not redirect_url:
        redirect_url = get_default_redirect(request)
    return HttpResponseRedirect(redirect_url)


def complete_signup(request, user, success_url, signal_kwargs={}):
    signals.user_signed_up.send(sender=user.__class__, 
                                request=request, 
                                user=user,
                                **signal_kwargs)
    return perform_login(request, user, redirect_url=success_url)


def get_primary_email(user):
    from models import EmailAddress
    try:
        primary_email = EmailAddress.objects.get(user=user, primary=True)
        return primary_email
    except EmailAddress.DoesNotExist:
        return False
    
    
def setup_user_email(request, user):
    from models import EmailAddress
    """
    Creates proper EmailAddress for the user that was just signed
    up. Only sets up, doesn't do any other handling such as sending
    out email confirmation mails etc.
    """
    print '---setup_user_email ---',
    
    user_email = user.email
    #check for verified email
    adapter = get_adapter()
    verified_email = adapter.is_email_verified(request)

    # check if the new user already has a primary email saved (from google?)
    primary_email_object = get_primary_email(user)

    print 'verified_email: ', verified_email
    print 'primary_email: ', primary_email_object
    print 'user_email: ', user.email
    
    emails = []
    if verified_email:
        emails.append({'email':verified_email, 'verified':True, 'primary':None})
    # only append user.email if it is not the same as verified email
    if user.email and user.email != verified_email:
        print '--user emial not equal verified email'
        emails.append({'email':user.email, 'verified':False, 'primary':None})
    print 'emails: ', emails
    
    if primary_email_object:
        emails = [ed for ed in emails if ed['email'] != primary_email_object.email]
    
    print 'unique emails: ', emails
    
    for e in emails:#TODO: make test for each email bovee
        '''this section is not done '''

        if primary_email_object and e['verified']:
            # check if the primary email is verified
            if primary_email_object.verified == True :
                primary_state = False
            elif primary_email_object.verified == False:
                # if the primary_email_object is not varified and new_email is 
                # the new_email becomes primary
                primary_email_object.primary = False
                print 'remove primary from primary_email: ', primary_email_object
                primary_email_object.save()
                primary_state = True
                primary_email_object = False
                # the primary_mail remains primary
        #since there is no primary_email the new_email is.
        else:
            primary_state = True
            primary_email_object = False
        
        e['primary']=primary_state
    
    #make sure there is a primary email
    if len(emails) == 1 and not primary_email_object:
        emails[0]['primary'] = True
    if len(mails) == 0:
        return

    for e in emails:
        print 'saving email: ', e
        email_address = EmailAddress.objects.create(user=user,
                                                    email=e['email'],
                                                    verified=e['verified'],
                                                    primary=e['primary'])
    return email_address

def send_email_confirmation(request, user, email_address=None):
    """
    E-mail verification mails are sent:
    a) Explicitly: when a user signs up
    b) Implicitly: when a user attempts to log in using an unverified
    e-mail while EMAIL_VERIFICATION is mandatory.

    Especially in case of b), we want to limit the number of mails
    sent (consider a user retrying a few times), which is why there is
    a cooldown period before sending a new mail.
    """
    from models import EmailAddress, EmailConfirmation

    COOLDOWN_PERIOD = timedelta(minutes=3)
    email = user.email
    if (email 
        and app_settings.EMAIL_VERIFICATION != EmailVerificationMethod.NONE):
        try:
            if email_address is None:
                email_address = EmailAddress.objects.get(user=user,
                                                         email__iexact=email)
            if not email_address.verified:
                send_email = not EmailConfirmation.objects \
                    .filter(sent__gt=now() - COOLDOWN_PERIOD,
                            email_address=email_address) \
                    .exists()
                if send_email:
                    email_address.send_confirmation(request)
            else:
                send_email = False
        except EmailAddress.DoesNotExist:
            send_email = True
            email_address = EmailAddress.objects.add_email(request,
                                                           user, 
                                                           user.email, 
                                                           confirm=True)
            assert email_address
        # At this point, if we were supposed to send an email we have sent it.
        if send_email:
            messages.info(request,
                _(u"Confirmation e-mail sent to %(email)s") % {"email": email}
            )

def sync_user_email_addresses(user):
    """
    Keep user.email in sync with user.emailadress_set.

    Under some circumstances the user.email may not have ended up as
    an EmailAddress record, e.g. in the case of manually created admin
    users.
    """
    from models import EmailAddress
    if user.email and not EmailAddress.objects.filter(user=user,
                                                      email=user.email).exists():
        if app_settings.UNIQUE_EMAIL and EmailAddress.objects.filter(email=user.email).exists():
            # Bail out
            return
        EmailAddress.objects.create(user=user,
                                    email=user.email,
                                    primary=False,
                                    verified=False)


def random_token(extra=None, hash_func=hashlib.sha256):
    if extra is None:
        extra = []
    bits = extra + [str(random.SystemRandom().getrandbits(512))]
    return hash_func("".join(bits)).hexdigest()
