from django.contrib import admin

# Register your models here.
from home.models import ArticleCategory, Article, Comment

admin.site.register(ArticleCategory)
admin.site.register(Article)
admin.site.register(Comment)
