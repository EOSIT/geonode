from actstream.models import Action
from django.views.generic import ListView


class RecentActivity(ListView):
    """
    Returns recent public activity.
    """
    context_object_name = 'action_list'
    #queryset = Action.objects.filter(public=True)[:15]
    template_name = 'social/activity_list.html'
    
    def get_queryset(self):
        if settings.LOCKDOWN_GROUP_PROFILE:
            if self.request.user.is_staff:
                return Action.objects.filter(public=True)[:15]
            else:
                return Action.objects.filter(public=True, user=self.request.user)[:15]
        return Action.objects.filter(public=True)[:15]
