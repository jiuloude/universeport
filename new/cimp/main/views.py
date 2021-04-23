from django.http import JsonResponse

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.hashers import make_password
import json
import traceback
from .models import User, Notice, News
from config.settings import UPLOAD_DIR
from datetime import datetime
from random import randint
from django.core.paginator import Paginator, EmptyPage
from django.db.models import Q


class SignHandler:
    def handle(self, request):
        pd = json.loads(request.body)

        action = pd.get('action')

        request.pd = pd

        if action == 'signin':
            return self.signin(request)
        elif action == 'signout':
            return self.signout(request)
        else:
            return JsonResponse({'ret': 2, 'msg': 'action参数错误'})

    # 登录处理
    def signin(self, request):
        # 从 HTTP POST 请求中获取用户名、密码参数
        userName = request.pd.get('username')
        passWord = request.pd.get('password')

        # 使用 Django auth 库里面的 方法校验用户名、密码
        user = authenticate(username=userName, password=passWord)

        # 如果能找到用户，并且密码正确
        if user is not None:
            if user.is_active:
                if user.is_superuser:
                    login(request, user)
                    # 在session中存入用户类型
                    return JsonResponse(
                        {
                            "ret": 0,
                            "usertype": user.usertype,
                            "userid": user.id,
                            "realname": user.realname,
                        }
                    )
                else:
                    return JsonResponse({'ret': 1, 'msg': '请使用管理员账户登录'})
            else:
                return JsonResponse({'ret': 0, 'msg': '用户已经被禁用'})

        # 否则就是用户名、密码有误
        else:
            return JsonResponse({'ret': 1, 'msg': '用户名或者密码错误'})

    # 登出处理
    def signout(self, request):
        # 使用登出方法
        logout(request)
        return JsonResponse({'ret': 0})


class AccountHandler:
    def handle(self, request):
        if request.method == 'GET':
            pd = request.GET
        else:
            pd = json.loads(request.body)

        request.pd = pd

        action = pd.get('action')

        if action == 'listbypage':
            return self.listbypage(request)
        elif action == 'addone':
            return self.addone(request)
        elif action == 'modifyone':
            return self.modifyone(request)
        elif action == 'deleteone':
            return self.deleteone(request)
        else:
            return JsonResponse({'ret': 2, 'msg': 'action参数错误'})

    # 登录处理
    def addone(self, request):

        data = request.pd.get('data')

        ret = User.addone(data)

        return JsonResponse(ret)

    def listbypage(self, request):

        pagenum = int(request.pd.get('pagenum'))
        pagesize = int(request.pd.get('pagesize'))
        keywords = request.pd.get('keywords')

        ret = User.listbypage(pagenum, pagesize, keywords)

        return JsonResponse(ret)

    def modifyone(self, request):

        newdata = request.pd.get('newdata')
        oid = request.pd.get('id')

        ret = User.modifyone(oid, newdata)

        return JsonResponse(ret)

    def deleteone(self, request):

        oid = request.pd.get('id')

        ret = User.deleteone(oid)

        return JsonResponse(ret)


class UploadHandler:
    def handle(self, request):
        uploadFile = request.FILES['upload1']

        filetype = uploadFile.name.split('.')[-1]
        if filetype not in ['jpg', 'png']:
            return JsonResponse({'ret': 430, 'msg': '只能上传jpg或者png'})

        if uploadFile.size > 10*1024*1024:
            return JsonResponse({'ret': 431, 'msg': '文件太大'})

        suffix = datetime.now().strftime('%Y%m%d%H%M%S_') + str(randint(0, 999999))
        filemane = f'{request.user.id}_{suffix}.{filetype}'

        with open(f'{UPLOAD_DIR}/{filemane}', 'wb') as f:
            fbytes = uploadFile.read()
            f.write(fbytes)

        return JsonResponse({'ret': 0, 'url': f'/upload{filemane}'})

class NoticeHandler:
    def handle(self, request):
        if request.method == 'GET':
            pd = request.GET
        else:
            pd = json.loads(request.body)
        action = pd.get('action')
        if action == 'getone':
            return self.getone(request)
        elif action == 'addone':
            return self.addone(request)
        elif action == 'listbypage_allstate':
            return self.listbypage_allstate(request)
        elif action == 'listbypage':
            return self.listbypage(request)
        elif action == 'modifyone':
            return self.modifyone(request)
        elif action == 'banone':
            return self.banone(request)
        elif action == 'publishone':
            return self.publishone(request)
        elif action == 'deleteone':
            return self.deleteone(request)
        else:
            return JsonResponse({'ret': 2, 'msg': 'action参数错误'})

    def listbypage(self, request):
        try:
            pagenum = int(request.pd.get('pagenum'))
            pagesize = int(request.pd.get('pagesize'))
            keywords = request.pd.get('keywords')
            qs = Notice.objects.values('id', 'pubdate', 'author', 'author__realname', 'title', 'content', 'status') \
                .order_by('-id')
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

    def listbypage_allstate(self, request):
        try:
            pagenum = int(request.pd.get('pagenum'))
            pagesize = int(request.pd.get('pagesize'))
            keywords = request.pd.get('keywords')
            qs = Notice.objects.values('id', 'pubdate', 'author', 'author__realname', 'title', 'content', 'status') \
                .order_by('-id')
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


    def getone(self, request):
        try:
            noticeid = int(request.pd.get('id'))
            pagesize = int(request.pd.get('pagesize'))
            qs = Notice.objects.values('id', 'pubdate', 'author', 'author__realname', 'title', 'content', 'status')\
                .order_by('-id')

            pgnt = Paginator(qs, pagesize)

            # 从数据库中读取数据，指定读取其中第几页
            page = pgnt.page(noticeid)

            # 将 QuerySet 对象 转化为 list 类型
            retlist = list(page)

            # total指定了 一共有多少数据
            return {'ret': 0, 'item': retlist, 'total': pgnt.count}

        except EmptyPage:
            return {'ret': 0, 'item': [], 'total': 0}

        except:
            err = traceback.format_exc()
            return {'ret': 2, 'msg': err}

    def addone(self, request):
        data = request.pd.get('data')

        try:
            notice = Notice.objects.create(
                title=data['title'],
                content=data['content']
            )

            return {'ret': 0, 'id': notice.id}
        except:
            err = traceback.format_exc()
            return {'ret': 2, 'msg': err}

    def modifyone(self, request):
        newdata = request.pd.get('newdata')
        oid = request.pd.get('id')

        try:
            notice = Notice.objects.get(id=oid)

            if 'title' in newdata:
                title = newdata['title']
                if Notice.objects.filter(title=title).exists():
                    return {'ret': 3, 'msg': f'名为{title}的通知已经存在'}

            for field, value in newdata.items():
                setattr(notice, field, value)

            notice.save()

            return {'ret': 0}
        except Notice.DoesNotExist:
            return {'ret': 2, 'msg': f'id为{oid}的消息不存在'}
        except:
            err = traceback.format_exc()
            return {'ret': 2, 'msg': err}

    def banone(self, request):
        oid = request.pd.get('id')
        status = request.pd.get('status')

        try:
            notice = Notice.objects.get(id=oid)

            setattr(notice, status, 3)

            notice.save()

            return {'ret': 0}
        except Notice.DoesNotExist:
            return {'ret': 2, 'msg': f'id为{oid}的消息不存在'}
        except:
            err = traceback.format_exc()
            return {'ret': 2, 'msg': err}

    def publishone(self, request):
        oid = request.pd.get('id')
        status = request.pd.get('status')

        try:
            notice = Notice.objects.get(id=oid)

            if status==3:

                return {'ret': 2, 'msg': f'id为{oid}的消息没有被封禁'}

            setattr(notice, status, 1)

            notice.save()

            return {'ret': 0}
        except Notice.DoesNotExist:
            return {'ret': 2, 'msg': f'id为{oid}的消息不存在'}
        except:
            err = traceback.format_exc()
            return {'ret': 2, 'msg': err}

    def deleteone(self, request):

        oid = request.pd.get('id')
        try:
            notice = Notice.objects.get(id=oid)

            notice.delete()

            return {'ret': 0}

        except Notice.DoesNotExist:
            return {'ret': 2, 'msg': f'id为{oid}的消息不存在'}

        except:
            err = traceback.format_exc()
            return {'ret': 2, 'msg': err}


class NewsHandler:
    def handle(self, request):
        if request.method == 'GET':
            pd = request.GET
        else:
            pd = json.loads(request.body)
        action = pd.get('action')
        if action == 'getone':
            return self.getone(request)
        elif action == 'addone':
            return self.addone(request)
        elif action == 'listbypage_allstate':
            return self.listbypage_allstate(request)
        elif action == 'listbypage':
            return self.listbypage(request)
        elif action == 'modifyone':
            return self.modifyone(request)
        elif action == 'banone':
            return self.banone(request)
        elif action == 'publishone':
            return self.publishone(request)
        elif action == 'deleteone':
            return self.deleteone(request)
        else:
            return JsonResponse({'ret': 2, 'msg': 'action参数错误'})

    def listbypage(self, request):
        try:
            pagenum = int(request.pd.get('pagenum'))
            pagesize = int(request.pd.get('pagesize'))
            keywords = request.pd.get('keywords')
            qs = News.objects.values('id', 'pubdate', 'author', 'author__realname', 'title', 'content', 'status') \
                .order_by('-id')
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

    def listbypage_allstate(self, request):
        try:
            pagenum = int(request.pd.get('pagenum'))
            pagesize = int(request.pd.get('pagesize'))
            keywords = request.pd.get('keywords')
            qs = News.objects.values('id', 'pubdate', 'author', 'author__realname', 'title', 'content', 'status') \
                .order_by('-id')
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


    def getone(self, request):
        try:
            noticeid = int(request.pd.get('id'))
            pagesize = int(request.pd.get('pagesize'))
            qs = News.objects.values('id', 'pubdate', 'author', 'author__realname', 'title', 'content', 'status')\
                .order_by('-id')

            pgnt = Paginator(qs, pagesize)

            # 从数据库中读取数据，指定读取其中第几页
            page = pgnt.page(noticeid)

            # 将 QuerySet 对象 转化为 list 类型
            retlist = list(page)

            # total指定了 一共有多少数据
            return {'ret': 0, 'item': retlist, 'total': pgnt.count}

        except EmptyPage:
            return {'ret': 0, 'item': [], 'total': 0}

        except:
            err = traceback.format_exc()
            return {'ret': 2, 'msg': err}

    def addone(self, request):
        data = request.pd.get('data')

        try:
            news = News.objects.create(
                title=data['title'],
                content=data['content']
            )

            return {'ret': 0, 'id': news.id}
        except:
            err = traceback.format_exc()
            return {'ret': 2, 'msg': err}

    def modifyone(self, request):
        newdata = request.pd.get('newdata')
        oid = request.pd.get('id')

        try:
            news = News.objects.get(id=oid)

            if 'title' in newdata:
                title = newdata['title']
                if News.objects.filter(title=title).exists():
                    return {'ret': 3, 'msg': f'名为{title}的通知已经存在'}

            for field, value in newdata.items():
                setattr(news, field, value)

            news.save()

            return {'ret': 0}
        except News.DoesNotExist:
            return {'ret': 2, 'msg': f'id为{oid}的消息不存在'}
        except:
            err = traceback.format_exc()
            return {'ret': 2, 'msg': err}

    def banone(self, request):
        oid = request.pd.get('id')
        status = request.pd.get('status')

        try:
            news = News.objects.get(id=oid)

            setattr(news, status, 3)

            news.save()

            return {'ret': 0}
        except News.DoesNotExist:
            return {'ret': 2, 'msg': f'id为{oid}的消息不存在'}
        except:
            err = traceback.format_exc()
            return {'ret': 2, 'msg': err}

    def publishone(self, request):
        oid = request.pd.get('id')
        status = request.pd.get('status')

        try:
            news = News.objects.get(id=oid)

            if status==3:

                return {'ret': 2, 'msg': f'id为{oid}的消息没有被封禁'}

            setattr(news, status, 1)

            news.save()

            return {'ret': 0}
        except News.DoesNotExist:
            return {'ret': 2, 'msg': f'id为{oid}的消息不存在'}
        except:
            err = traceback.format_exc()
            return {'ret': 2, 'msg': err}

    def deleteone(self, request):

        oid = request.pd.get('id')
        try:
            news = News.objects.get(id=oid)

            news.delete()

            return {'ret': 0}

        except News.DoesNotExist:
            return {'ret': 2, 'msg': f'id为{oid}的消息不存在'}

        except:
            err = traceback.format_exc()
            return {'ret': 2, 'msg': err}







