# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Keys',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('username', models.CharField(max_length=255)),
                ('key_id', models.BigIntegerField()),
                ('public_key', models.TextField()),
                ('last_resort', models.BooleanField(default=False)),
                ('device_id', models.BigIntegerField(default=1)),
            ],
        ),
    ]
