var url = window.location.pathname;

$(function(){



    //访问首页自动登出
    if (url == '/') {
		$.get("/logout");
	}

	if (url == '/settings') {
		user_list_all();
		setTimeout(function() {
		var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'))
        var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {

        return new bootstrap.Popover(popoverTriggerEl)
        })
        }, 1000);


	}

    //访问首页自动登出
    if (url == '/dest') {
   var iframe = document.createElement("iframe");
    //等待iframe 加载
     iframe.src = "/dest/url";
        if (iframe.attachEvent){
        iframe.attachEvent("onload", function(){
            setTimeout(function() {
                 $('#loading').removeClass('animate__fadeInDown');
                 $('#loading').addClass('animate__fadeOutDown');
                 $('iframe').addClass('animate__animated animate__fadeIn');
           	}, 2500);


        });
        } else {
        iframe.onload = function(){
            setTimeout(function() {
                 $('#loading').removeClass('animate__fadeInDown');
                 $('#loading').addClass('animate__fadeOutDown');
                 $('iframe').addClass('animate__animated animate__fadeIn');
           	}, 2500);

        };
        }
      document.body.appendChild(iframe);
	}

// 过期认证
if (url == '/return') {
    setTimeout(function() {
       window.location.replace("/");
     }, 4500);
}


    //点击验证码刷新
    $("#valid-img").click(function () {
        $(this)[0].src ='/code?'+Math.random()
    })

    //OTP认证取消隐藏
    $("#two-factor").change(function() {
        var selectedValue = $(this).val();
        if (selectedValue === "2") {
          // 复选框被选中时显示元素
          $("#OTP-windows").show();
        } else {
          // 复选框未被选中时隐藏元素
          $("#OTP-windows").hide();
        }
      });
});

//登出
function logout(){
    $.get("/logout",function(){
        alert('已登出');
        window.location.replace("/");
    });
}

//登录功能
function login() {
	var username = $(".login-form").find("#username").val();
	var password = $(".login-form").find("#password").val();
	var captcha = $(".login-form").find("#captcha").val();
	var id = $(".login-form").find("#OTP-id").val();
	var params = {username:username,password:password,code:captcha,'OTP-id':id};
	var origin_buttom_html = $("#loginbutton").html();

    function clean() {
        $("#loginbutton").html(origin_buttom_html);
        $("#loginbutton").attr("disabled",false);
        $('input').removeClass('is-invalid');
        $("#alert").removeClass('alert-danger');
        $('#captcha').val('');
        $("#alert").hide();
    }

	 $.ajax({
            //提交数据的类型 POST GET
            type:"POST",
            //提交的网址
            url: "/login",
            //提交的数据
            data: params,
            datatype: "text",
            //在请求之前调用的函数
            beforeSend:function(){
                $('input').attr("disabled",true);
            	$("#loginbutton").attr("disabled",true);
            },
            //成功返回之后调用的函数
            success:function(data){
                $("#alert").show();
                $('#valid-img')[0].src ='/code?'+Math.random();
                $('input').attr("disabled",false);
           		if (data.includes("登录成功")) {
           			$("#alert").addClass("alert-success").html(data);
           			setTimeout(function() {
						window.location.replace("/dest");
		 			}, 3000);
           		}
           		else if (data.includes("用户名或密码错误")) {
           		    $("#alert").addClass("alert-danger").html(data);
           			$('.up').addClass('is-invalid');
           			setTimeout(function() {
           				clean();
           			}, 3000);
           		}
           		else if (data.includes("验证码错误")) {
           		    $("#alert").addClass("alert-danger").html(data);
           			$('#captcha').addClass('is-invalid');
           			setTimeout(function() {
                        clean();
           			}, 3000);
           		}
           		else if (data.includes("动态口令错误")) {
           		    $("#alert").addClass("alert-danger").html(data);
           			$('#OTP-id').addClass('is-invalid');
           			setTimeout(function() {
                        clean();
           			}, 3000);
           		}
           		else if (data.includes("该账号已开启二步认证，请填写动态口令")) {
           		    $("#alert").addClass("alert-danger").html(data);
           			$('#two-factor').addClass('is-invalid');
           			setTimeout(function() {
           			    $('#two-factor').removeClass('is-invalid');
                        clean();
           			}, 3000);
           		}
           		else if (data.includes("登录多次失败，已进入锁定期")) {
           		    $("#alert").addClass("alert-danger").html(data);
           			$('.up').addClass('is-invalid');
           			setTimeout(function() {
                        clean();
           			}, 3000);
           		}
           		else if (data.includes("用户被禁用")) {
           		    $("#alert").addClass("alert-danger").html(data);
           			$('#username').addClass('is-invalid');
           			setTimeout(function() {
                        clean();
           			}, 3000);
           		}
            } ,
            //调用出错执行的函数
            error: function(){
                $("#alert").addClass("alert-danger").html("网络错误");
                setTimeout(function() {
						clean();
		 			}, 3000);
            }
         });
}


// 设置提交
function setting_submit(){
    var s = $('#all_settings');
    var info = {
        'title': s.find("#title").val(),
        'dest_url' : s.find("#dest_url").val(),
        'white_IP_list' : s.find("#white_IP_list").val(),
        'set_login_failure_time' : s.find("#set_login_failure_time").val(),
        'set_login_lock_time' : s.find("#set_login_lock_time").val(),
        'session_long' : s.find("#session_long").val(),
        'id' : '1'
    };

    var formValid = true;
        s.find("input").each(function() {
          if ($(this).val() === "") {
            alert("请填写所有必填字段！");
            formValid = false;
            return false; // 停止遍历
          }
        });
        if (!formValid) {
          event.preventDefault(); // 阻止表单提交
        } else if (formValid) {
            $.ajax({
                //提交数据的类型 POST GET
                type:"PUT",
                //提交的网址
                url: "/modify/settings",
                //提交的数据
                data: info,
                datatype: "text",
                //成功返回之后调用的函数
                success:function(data){
                    if (data.includes("have changed")) {
                        alert('修改成功，即将刷新！')
                        window.location.replace("/settings");
                    }
                    else if (data.includes("no changed")) {
                        alert('没有任何修改')
                    }

                } ,
                //调用出错执行的函数
                error: function(){
                    alert("网络错误");
                    window.location.replace("/settings");
                }
             });

         }
}




//生成用户列表
function user_list_all() {

function create_link(str) {
    var base64_img = jrQrcode.getQrBase64('otpauth://totp/login_dengbao?secret='+str);
    var over = '<a href="#" class="qrcode-href" data-bs-container="body" data-bs-toggle="popover" data-bs-placement="right" data-bs-html="true" data-bs-content="<div id=\'qrcode\'><p>请用谷歌验证器或T盾其他令牌器扫描</p><img src='+base64_img+'></div>">'+str+'</a>'
    return over
}

function addhtml(username){

    return  ` <div class="dropdown">
        <button class="btn btn-secondary btn-sm dropdown-toggle" type="button" data-bs-toggle="dropdown" aria-expanded="false">
        操作
        </button>
        <ul class="dropdown-menu" aria-labelledby="dropdownMenu">
        <li><a class="dropdown-item" href="#" onclick="change_password('${username}')">修改密码</a></li>
        <li><a class="dropdown-item" href="#" onclick="lock_unlock('${username}')">锁定/解锁账号</a></li>
        <li><a class="dropdown-item" href="#" onclick="change_OTP('${username}')">开启/关闭动态口令</a></li>
        <li><a class="dropdown-item" href="#" onclick="delete_user('${username}');">删除该用户</a></li>
        </ul>
        </div>
`
}

      $.get("/user/show", function(data) {
        var tableBody = $("#userlist tbody");
        $.each(data, function(index, item) {
          var result = item.result;
          var newRow = $("<tr username="+result.username+">");
          newRow.append($("<td>").text(result.id));
          newRow.append($("<td>").text(result.username));
          newRow.append($("<td>").text(result.character));
          newRow.append($("<td>").text(result.otp_enable));
          newRow.append($("<td>").html(create_link(result.OTP_id)));
          newRow.append($("<td>").text(result.user_enable));
          newRow.append($("<td>").html(addhtml(result.username)));
          tableBody.append(newRow);
        });
      });



}

