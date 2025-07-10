use serde::{Serialize};
#[derive(Serialize, Debug)]
pub struct Model{
    pub name: String
}
impl  Model{
 pub  fn new( name: String) -> Self{
        Self {
            name,
        }
    }
}
#[derive(Serialize, Debug)]
pub struct  MessageResponse{
pub role: String,
pub content: String
}
impl  MessageResponse {
    pub fn new(role: String, content: String) -> Self{
        Self { 
            role,
            content
        }
    }
}
#[derive(Serialize, Debug)]
pub struct  OPenAiRequest{
    pub model: String,
    pub messages: Vec<MessageResponse>
}

impl OPenAiRequest{
    pub fn new( model: String) -> Self{

        Self{
            model,
            messages: Vec::new()
        }
    }}