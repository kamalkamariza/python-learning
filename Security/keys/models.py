# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models


class Users(models.Model):
    user_number = models.TextField()
    user_publicKey = models.TextField()
    objects = models.Manager()

    def __unicode__(self):
        return self.user_number
