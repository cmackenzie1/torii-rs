use askama::Template;
use torii::User;

use crate::Todo;

#[derive(Default)]
pub struct Context {
    pub user: Option<User>,
}

#[derive(Template)]
#[template(path = "todo.partial.html")]
pub struct TodoPartial {
    pub todo: Todo,
}

#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexTemplate {
    pub context: Context,
    pub todos: Vec<Todo>,
}

#[derive(Template)]
#[template(path = "sign_up.html")]
pub struct SignUpTemplate {
    pub context: Context,
}

#[derive(Template)]
#[template(path = "sign_in.html")]
pub struct SignInTemplate {
    pub context: Context,
}
