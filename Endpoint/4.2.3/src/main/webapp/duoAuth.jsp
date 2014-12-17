
<%@ page language="java" contentType="text/html; charset=UTF-8"
         pageEncoding="UTF-8"%>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
"http://www.w3.org/TR/html4/loose.dtd">
<html>

<script src="js/Duo-Web-v1.bundled.js"></script>
<script type="text/javascript">
		var value = '<%=request.getParameter("signreq")%>' ;
		var sessionDataKey = '<%=request.getParameter("sessionDataKey")%>';
		var host = '<%=request.getParameter("duoHost")%>' ;
		Duo.init({
		    'host': host,
		    'sig_request': value,
		    'post_action': '../../commonauth',
		    'sessionDataKey': sessionDataKey
		  });
</script>
<body>
<iframe id="duo_iframe" width="620" height="330" frameborder="0"></iframe>
</body>
</html>