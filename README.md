# 스프링 시큐리티 내부 구조 개념

## 전반적인 동작 원리

### 시큐리티 의존성이 없는 경우
![request-with-no-security](./resources/request-with-no-security.png)
- 클라이언트의 요청은 서버 컴퓨터의 WAS(톰캣)의 필터들을 통과한 뒤 스프링 컨테이너의 컨트롤러에 도달한다
- 컨트롤러 앞단에 `DispatcherServlet` 통해 `Handler`를 찾는 여러 과정이 있다
  ![client-filter-example](./resources/client-filter-example.png) 

### 시큐리티 의존성 추가 후
![request-with-security](./resources/request-with-security.png) 
- WAS의 필터단에서 요청을 가로챈 후 시큐리티의 역할을 수행한다
- 순서
  - WAS의 필터에 하나의 필터를 만들어서 넣고 해당 필터에서 요청을 가로챈다
  - 해당 요청은 스프링 컨테이너 내부에 구현되어 있는 스프링 시큐리티 감시 로직을 거친다
  - 시큐리티 로직을 마친 후 다시 WAS의 다음 필터로 복귀한다

![security-filter-structure](./resources/security-filter-structure.png)
- 클라이언트 요청이 필터단을 거치면서 `DelegatingFilterProxy`와 `FilterChainProxy`가 요청을 가로챈다
  - `DelegatingFilterProxy`: 스프링 `Bean`을 찾아 요청을 넘겨주는 서블릿 필터
  - `FilterChainProxy`: 스프링 시큐리티 의존성을 추가하면 `DelegatingFilterProxy`에 의해 호출되는 `SecurityFilterChain`들을 들고 있는 `Bean`
- 가로챈 요청을 `SecurityFilterChain`에 보내 시큐리티 로직을 거치고 다시 다음 필터로 복귀한다

### 스프링 시큐리티 로직 구성
![spring-security-structure](./resources/spring-security-structure.png)
- 스프링 시큐리티 로직은 여러개의 필터들이 나열된 체인 형태로 구성되어 있다
- 각각의 필터에서 CSRF, 로그아웃, 로그인, 인가 등 여러 작업을 수행한다
- 시큐리티 필터 체인은 일연의 과정들을 수행하는 필터들의 묶음이다
- 여러개의 시큐리티 필터 체인을 가질 수 있다
  ![spring-security-multiple-filter-chain](./resources/spring-security-multiple-filter-chain.png) 

## DelegatingFilterProxy, FilterChainProxy

### DelegatingFilterProxy
- 클라이언트의 요청을 가로채서 스프링 컨테이너에 들어 있는 `FilterChainProxy`로 요청을 던져준다
- 요청을 전달하는 매개체 역할이다
- 스프링 시큐리티 의존성을 추가하면 `SecurityAutoConfiguration`를 통해 자동 등록된다
  - `SecurityAutoConfiguration`은 스프링 시큐리티 의존성 내부에 포함되어 있다

### FilterChainProxy
- `DelegatingFilterProxy`로 부터 요청을 전달 받는다
- 등록되어 있는 시큐리티 필터 체인들 중 요청에 알맞은 시큐리티 필터 체인에 요청을 전달한다 

## SecurityFilterChain 등록

### DefaultSecurityFilterChain
- 스프링 시큐리티 의존성을 추가하면 기본적인 `DefaultSecurityFilterChain` 하나가 등록된다
  - 어플리케이션을 실행하면 기본적으로 사용할 수 있는 로그인 창 같은 기능을 제공한다

### 커스텀 SecurityFilterChaine 등록 
- 내가 원하는 `SecurityFilterChain`을 등록하기 위해서는 `SecurityFilterChain`을 리턴하는 `@Bean` 메서드를 등록하면 되고 여러개 등록할 수 있다
  ```java
	@Configuration
	@EnableWebSecurity
	public class SecurityConfig {

			@Bean
			public SecurityFilterChain filterChain1(HttpSecurity http) throws Exception{

					return http.build();
			}

			@Bean
			public SecurityFilterChain filterChain2(HttpSecurity http) throws Exception {

					return http.build();
			}
	}
  ``` 
### 멀티 SecurityFilterChain 중 하나 선택
- `FilterChainProxy`는 N개의 `SecurityFilterChain` 중 하나를 선택해서 요청을 전달한다
- 선택 기준은 아래와 같다
  - 등록 인덱스 순
  - 필터 체인에 대한 `RequestMatcher` 값이 일치하는지 확인
    - 여기서 `RequestMatcher`는 인가 작업이 아닌 `SecurityFilterChain`에 대한 `RequestMatcher` 설정으로 아래에서 설명한다

### 멀티 SecurityFilterChain 경로 설정 (필수)
- 경로 설정을 하지 않으면 아래와 같은 문제가 발생할 수 있다
  - N개의 `SecurityFilterChain`이 모두 `"/**"` 경로에서 매핑된다
  - 모든 요청이 첫번째로 등록되어 있는 `SecurityFilterChain`만 거치게 된다 
 
- 문제 상황 예시
	```java
	@Bean
	public SecurityFilterChain filterChain1(HttpSecurity http) throws Exception {

			http.authorizeHttpRequests((auth) -> auth.requestMatchers("/user").permitAll());

			return http.build();
	}

	@Bean
	public SecurityFilterChain filterChain2(HttpSecurity http) throws Exception {

			http.authorizeHttpRequests((auth) -> auth.requestMatchers("/admin").permitAll());

			return http.build();
	}
	``` 
	- 2개의 커스텀 `SecurityFilterChain`을 등록하고 각각 `"/user`, `"/admin"` 경로에 대해서 `permitAll()` 설정을 한다
	- 이후 `"/admin"` 경로로 요청을 보내면 별다른 인증 과정없이 컨트롤러로 연결된다고 생각하겠지만 예상치 못한 응답이 발생한다
	- 그 이유는 `filterChain1`이 `filterChain2` 보다 먼저 등록되어 있고 `SecurityFilterChain`에 대한 경로 설정을 하지 않았기 때문에 `filterChain1`, `filterChain2` 모두 `"/**"` 경로에 대해서 반응하기 때문이다
	- 따라서, `"/admin"` 경로로 보낸 요청은 `filterChain1`으로 전달되고 `filterChain1` 내부에는 `"/admin"`에 대한 설정이 없기 때문에 요청이 거부된다

- 해결 방법 예시 
  ```java
	@Bean
	public SecurityFilterChain filterChain1(HttpSecurity http) throws Exception {

			http
				.securityMatchers((auth) -> auth.requestMatchers("/user"))
				.authorizeHttpRequests((auth) -> auth.requestMatchers("/user").permitAll());

			return http.build();
	}

	@Bean
	public SecurityFilterChain filterChain2(HttpSecurity http) throws Exception {

			http
				.securityMatchers((auth) -> auth.requestMatchers("/admin"))
				.authorizeHttpRequests((auth) -> auth.requestMatchers("/admin").authenticated());

			return http.build();
	}
	``` 
	- `securityMatchers()`를 통해서 `SecurityFilterChain`에 대한 경로 설정(`RequestMatcher`)을 추가한다
	  - `filterChain1` -> `"/user"`
	  - `filterChain2` -> `"/admin"`

### 멀티 SecurityFilterChain 순서 설정 (선택)
- N개의 `SecurityFilterChain`을 만들고 등록되는 순서를 직접 지정하고 싶다면 `@Order` 어노테이션을 사용하면 된다
  ```java
	@Bean
	@Order(1)
	public SecurityFilterChain filterChain1(HttpSecurity http) throws Exception{

			return http.build();
	}

	@Bean
	@Order(2)
	public SecurityFilterChain filterChain2(HttpSecurity http) throws Exception {

			return http.build();
	}
	``` 

### 특정 요청은 필터를 거치지 않도록 설정

- `SecurityFilterChain`은 내부적으로 여러 가지 필터를 거치게 된다
- 이때, 서버의 자원을 사용하고 처리 시간이 발생하기 때문에 특정 요청은 필터를 거치지 않도록 설정할 수 있다
- 보통 정적 자원(이미지, CSS)의 경우 필터를 통과하지 않도록 설정한다
- 설정 시 필터 체인 내부에 필터가 없는 `SecurityFilterChain` 하나가 0번 인덱스로 설정된다
  ```java
	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {

			return web -> web.ignoring().requestMatchers("/img/**");
	}
	``` 