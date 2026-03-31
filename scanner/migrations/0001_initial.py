from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name='ScanJob',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('target', models.CharField(help_text='IP address or domain', max_length=255)),
                ('port_range', models.CharField(default='1-1024', max_length=50)),
                ('scan_type', models.CharField(default='tcp', max_length=50)),
                ('status', models.CharField(
                    choices=[('pending','Pending'),('running','Running'),('completed','Completed'),('failed','Failed')],
                    default='pending', max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('duration_seconds', models.FloatField(blank=True, null=True)),
                ('total_ports_scanned', models.IntegerField(default=0)),
                ('open_ports_count', models.IntegerField(default=0)),
                ('error_message', models.TextField(blank=True)),
            ],
            options={'ordering': ['-created_at']},
        ),
        migrations.CreateModel(
            name='PortResult',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('port', models.IntegerField()),
                ('is_open', models.BooleanField(default=False)),
                ('protocol', models.CharField(default='tcp', max_length=10)),
                ('service', models.CharField(blank=True, max_length=100)),
                ('service_version', models.CharField(blank=True, max_length=200)),
                ('banner', models.TextField(blank=True)),
                ('response_time_ms', models.FloatField(blank=True, null=True)),
                ('scan', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='scanner.scanjob')),
            ],
            options={'ordering': ['port'], 'unique_together': {('scan', 'port', 'protocol')}},
        ),
    ]
