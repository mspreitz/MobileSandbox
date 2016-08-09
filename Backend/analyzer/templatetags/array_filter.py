from django import template
register = template.Library()

@register.filter()
def is_string(val):
    print 'What'
    return isinstance(val, basestring)