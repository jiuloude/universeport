from django.db import models
import traceback
import time

# Create your models here.

from django.contrib.auth.models import AbstractUser
from django.contrib.auth.hashers import make_password, check_password

from django.db.models import Q
from django.core.paginator import Paginator, EmptyPage


class User(AbstractUser):
    id = models.BigAutoField(primary_key=True)

    # 用户类型
    # 1：超管/1000：普通管理员/2000：学生/3000：老师
    usertype = models.PositiveIntegerField()

    # 真实姓名
    realname = models.CharField(max_length=30, db_index=True)

    # 学号
    studentno = models.CharField(
        max_length=10,
        db_index=True,
        null=True, blank=True
    )

    # 备注描述
    desc = models.CharField(max_length=500, null=True, blank=True)

    REQUIRED_FIELDS = ['usertype', 'realname']

    class Meta:
        db_table = "clmp_user"

    @staticmethod
    def addone(data):
        try:
            user = User.objects.create(
                username=data['username'],
                password=make_password(str(['password'])),
                usertype=data['usertype'],
                realname=data['realname'],
                studentno=data['studentno'],
                desc=data['desc']
            )

            return {'ret': 0, 'id': user.id}
        except:
            err = traceback.format_exc()
            return {'ret': 2, 'msg': err}

    @staticmethod
    def listbypage(pagenum, pagesize, keywords):
        try:
            qs = User.objects.values('id', 'username', 'realname', 'studentno', 'desc', 'usertype').order_by('-id')
            if keywords:
                conditions = [Q(realname__contains=one) for one in keywords.split(' ') if one]
                query = Q()
                for condition in conditions:
                    query &= condition
                qs = qs.filter(query)

            pgnt = Paginator(qs, pagesize)

            # 从数据库中读取数据，指定读取其中第几页
            page = pgnt.page(pagenum)

            # 将 QuerySet 对象 转化为 list 类型
            retlist = list(page)

            # total指定了 一共有多少数据
            return {'ret': 0, 'item': retlist, 'total': pgnt.count, 'keywords': keywords}

        except EmptyPage:
            return {'ret': 0, 'item': [], 'total': 0, 'keywords': keywords}

        except:
            err = traceback.format_exc()
            return {'ret': 2, 'msg': err}

    @staticmethod
    def modifyone(oid, newdata):
        try:
            user = User.objects.get(id=oid)

            if 'username' in newdata:
                username = newdata['username']
                if User.objects.filter(username=username).exists():
                    return {'ret': 3, 'msg': f'登录名为{username}的用户已经存在'}

            if 'password' in newdata:
                user.password = make_password((newdata.pop('password')))

            for field, value in newdata.items():
                setattr(user, field, value)

            user.save()

            return {'ret': 0}
        except User.DoesNotExist:
            return {'ret': 2, 'msg': f'id为{oid}的用户不存在'}
        except:
            err = traceback.format_exc()
            return {'ret': 2, 'msg': err}

    def deleteone(oid):
        try:
            user = User.objects.get(id=oid)

            user.delete()

            return {'ret': 0}

        except User.DoesNotExist:
            return {'ret': 2, 'msg': f'id为{oid}的用户不存在'}

        except:
            err = traceback.format_exc()
            return {'ret': 2, 'msg': err}


class Notice(AbstractUser):
    id = models.BigAutoField(primary_key=True)

    # 创建时间
    pubdate = time.strftime('%Y%m%d',time.localtime(time.time()))

    # 创建者ID
    author = User.id

    author__realname = User.realname

    title = models.CharField(
        db_index=True,
        null=False, blank=False
    )

    content = models.CharField(
        db_index=True,
        null=False, blank=False
    )

    status = 1

    REQUIRED_FIELDS = ['title', 'content']

    class Meta:
        db_table = "clmp_notice"


class News(AbstractUser):
    id = models.BigAutoField(primary_key=True)

    # 创建时间
    pubdate = time.strftime('%Y%m%d',time.localtime(time.time()))

    # 创建者ID
    author = User.id

    author__realname = User.realname

    title = models.CharField(
        db_index=True,
        null=False, blank=False
    )

    content = models.CharField(
        db_index=True,
        null=False, blank=False
    )

    status = 1

    REQUIRED_FIELDS = ['title', 'content']

    class Meta:
        db_table = "clmp_notice"



