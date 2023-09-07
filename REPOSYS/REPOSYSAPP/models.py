from django.contrib.auth.models import User
from django.db import models

# Create your models here.

YEARS = (
    (u'FE', u'FE'),
    (u'SE', u'SE'),
    (u'TE', u'TE'),
    (u'BE', u'BE'),
)

DIV = (
    (u'A', u'A'),
    (u'B', u'B'),
)

BRANCH = (
    (u'INFT', u'Information Technology'),
    (u'CMPN', u'Computer Engineering'),
    (u'ETRX', u'Electronics Engieering'),
    (u'EXTC', u'Electronics and Telecommunication Engineering'),
    (u'BIOM', u'Biomedical Engineering'),
    (u'MNGT', u'Management Studies'),
)


class Student(models.Model):
    username = models.OneToOneField(User, on_delete=models.CASCADE, null=True, blank=True)
    first_name = models.CharField(max_length=225, null=True)
    last_name = models.CharField(max_length=225, null=True)
    roll_no = models.CharField(max_length=225, null=True)
    email = models.EmailField(max_length=225, null=True)
    branch = models.CharField(max_length=45, choices=BRANCH, default="")
    year = models.CharField(max_length=30, choices=YEARS, default="")
    date_of_add = models.DateField()
    div = models.CharField(max_length=30, choices=DIV, default="")
    mobile = models.CharField(max_length=10, null=True)
    profile_image = models.ImageField(upload_to="images/%Y/%m/%d/", null=True, blank=True)

    def __str__(self):
        return self.first_name + " " + self.last_name

    class Meta:
        db_table = "Student"


class Certificate(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    type_of_cert = models.CharField(max_length=225, null=True)
    name_of_event = models.CharField(max_length=225, null=True)
    auth_of_event = models.CharField(max_length=225, null=True)
    date_of_event = models.DateField()
    desc_of_event = models.CharField(max_length=225, null=True)
    upload_cert = models.FileField(upload_to="certificates/%Y/%m/%d/", null=True, blank=True)

    def __str__(self):
        return self.user

    class Meta:
        db_table = "Certificate"


class Education(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    qua_level = models.CharField(max_length=225, null=True)
    country = models.CharField(max_length=225, null=True)
    state = models.CharField(max_length=225, null=True)
    district = models.CharField(max_length=225, null=True)
    college_name = models.CharField(max_length=225, null=True)
    admission_year = models.DateField()
    result = models.CharField(max_length=225, null=True)
    stream = models.CharField(max_length=225, null=True)
    course_name = models.CharField(max_length=225, null=True)
    pass_year = models.DateField()
    percentage = models.CharField(max_length=225, null=True)
    completed = models.CharField(max_length=225, null=True)
    board_university = models.CharField(max_length=225, null=True)
    mode = models.CharField(max_length=225, null=True)
    attempts = models.CharField(max_length=225, null=True)
    upload_marksheet = models.FileField(upload_to="marksheets/%Y/%m/%d/", null=True, blank=True)

    def __str__(self):
        return self.user

    class Meta:
        db_table = "Education"
